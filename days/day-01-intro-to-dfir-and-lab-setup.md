# Day 01: Introduction to Digital Forensics & Building Your DFIR Lab

> **Phase 1: Foundations** · **Level:** 🟢 Beginner · **Time:** ~3–4 hours (reading + labs) · **Posted:** 2026-09-28
>
> **Tools today:** 🛠️ SIFT Workstation · 🛠️ CyberChef · 🛠️ Eric Zimmerman's Tools (EZ Tools)

---

## 🎯 Learning objectives

By the end of today you will be able to:

1. Define digital forensics and DFIR, and name the main branches.
2. Describe the forensic process and the incident response lifecycle.
3. Explain the core principles: Locard's exchange principle, order of volatility, forensic soundness and chain of custody.
4. Design an isolated forensic lab with a Linux and a Windows analysis workstation.
5. Install, configure and check **SIFT Workstation**, **CyberChef** and **EZ Tools**.
6. Recover your first deleted file from a disk image.

---

## Part 1: The lesson

### 1.1 What is digital forensics?

**Digital forensics** means using scientific, repeatable methods to **identify, preserve, collect, examine, analyse and report on digital evidence**. The results have to hold up to scrutiny, whether that is a court, a regulator, an HR panel or an incident post-mortem.

The important words are *scientific* and *repeatable*. Another qualified examiner, given the same evidence and the same method, should reach the same result.

Digital forensics answers the classic investigative questions:

| Question | Example in a digital case |
|----------|---------------------------|
| **What** happened? | Ransomware encrypted 400 file servers |
| **When** did it happen? | Initial access 2026-03-02 14:07 UTC, encryption started 2026-03-09 01:15 UTC |
| **Where** did it happen? | VPN appliance → jump host → domain controller → file servers |
| **How** did it happen? | Phishing, then stolen VPN credentials, then RDP lateral movement |
| **Who** did it? | Account `svc_backup` used from IP 203.0.113.50 (attribution is usually the hardest part) |
| **Why / what was the impact?** | 120 GB exfiltrated before encryption |

### 1.2 Branches of digital forensics

| Branch | Focus | Typical evidence | Where in this course |
|--------|-------|------------------|----------------------|
| **Computer / disk forensics** | Storage media and file systems | Disk images, deleted files, OS artifacts | Days 3–22 |
| **Memory forensics** | Volatile RAM | Processes, injected code, network connections, keys | Days 23–27 |
| **Network forensics** | Traffic and network logs | PCAP, NetFlow, Zeek logs, proxy/DNS/firewall logs | Days 28–32 |
| **Mobile forensics** | Phones and tablets | Android/iOS file systems, app databases, backups | Days 39–41 |
| **Malware forensics** | Malicious code | Samples, behaviour, IOCs | Days 42–47 |
| **Cloud forensics** | IaaS/SaaS environments | Audit logs (CloudTrail, M365 UAL), snapshots | Days 55–58 |
| **Other** | Databases, email, IoT, vehicles, drones, game consoles | Specialised formats | Throughout |

### 1.3 Digital forensics vs incident response vs DFIR

| | **Digital forensics (traditional)** | **Incident response** | **DFIR (the modern blend)** |
|---|---|---|---|
| Main goal | Establish facts to a legal standard | Stop the bleeding and restore the business | Both: answer the questions *and* contain the threat |
| Pace | Methodical, thorough | Fast, time-critical | Triage fast, then go deep where it matters |
| Typical output | Expert report, testimony | Containment actions, lessons learned | IR report, timeline, IOCs, root cause |
| Evidence scope | Often a few devices, fully imaged | Hundreds or thousands of endpoints | Targeted collection at scale plus deep dives |

In practice, most corporate "forensics" work today is **DFIR**. You use forensic techniques inside an incident response. The discipline is the same: preserve first, document everything, and never change the original.

### 1.4 The forensic process

Most models share the same six stages:

```
┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│ Identification│──▶│ Preservation │──▶│  Collection  │──▶│ Examination  │──▶│   Analysis   │──▶│  Reporting   │
│ what & where │   │ stop changes │   │ acquire copy │   │ extract data │   │ interpret it │   │ present facts│
└──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘
        ▲                                                                                              │
        └────────────────────────── documentation & chain of custody at every stage ──────────────────┘
```

- **Identification**: find the potential sources of evidence: laptops, servers, phones, cloud tenants, logs, backups, USB sticks, and the people who know about them.
- **Preservation**: stop evidence from changing or disappearing. Isolate the host from the network without powering it off, suspend log rotation, put legal holds in place, and photograph the scene.
- **Collection (acquisition)**: make forensically sound copies (images) and verify them with hashes.
- **Examination**: extract and filter the data: parse file systems, recover deleted files, decode artifacts.
- **Analysis**: interpret the data and build a timeline. Test your hypotheses against the evidence and draw conclusions.
- **Reporting**: present the findings clearly and objectively, with the method used and the limits of your conclusions.

**NIST SP 800-86** (*Guide to Integrating Forensic Techniques into Incident Response*) uses four phases: **Collection → Examination → Analysis → Reporting**. It describes the process as turning *media* into *data*, then *information*, then *evidence*.

### 1.5 The incident response lifecycle

You will meet three frameworks everywhere:

| Framework | Phases |
|-----------|--------|
| **NIST SP 800-61 Rev. 2** (classic) | Preparation → Detection & Analysis → Containment, Eradication & Recovery → Post-Incident Activity |
| **SANS PICERL** | **P**reparation → **I**dentification → **C**ontainment → **E**radication → **R**ecovery → **L**essons learned |
| **NIST SP 800-61 Rev. 3** (April 2025) | Rewrites incident response around the **NIST CSF 2.0** functions: *Govern, Identify, Protect* (preparation) and *Detect, Respond, Recover* (the incident itself), with continuous improvement |

Forensics sits mainly in **Detection & Analysis / Identification**: it answers *scope* and *root cause*, and those answers drive containment and eradication.

### 1.6 Core principles you must live by

#### Locard's Exchange Principle

> *"Every contact leaves a trace."* (Edmond Locard, forensic science pioneer)

In digital terms, every action on a system leaves artifacts: logs, registry changes, prefetch files, timestamps, memory structures. **That includes your own actions as an examiner.** Logging in to a suspect machine to "take a quick look" creates new artifacts and can overwrite old ones.

#### Order of volatility (RFC 3227)

Collect the most volatile evidence first. It disappears the soonest.

| Priority | Source | Lifetime |
|---------:|--------|----------|
| 1 | CPU registers, cache | Nanoseconds |
| 2 | Routing table, ARP cache, process table, kernel statistics, **memory (RAM)** | Seconds to minutes |
| 3 | Temporary file systems (`/tmp`, swap) | Minutes to hours |
| 4 | Disk | Days to years |
| 5 | Remote logging and monitoring data | Depends on retention |
| 6 | Physical configuration, network topology | Months |
| 7 | Archival media (backups, tapes) | Years |

> 💡 **Rule of thumb:** if a machine is running, capture **memory first** (Day 23), then triage artifacts, then the disk. Pulling the plug destroys RAM: running malware, network connections, encryption keys, command history.

#### Forensic soundness

- **Never work on the original.** Acquire an image, verify it with a hash, and analyse the copy.
- **Use write-blocking** (hardware or software) when you acquire from storage media.
- **Keep changes to a minimum, and document any change you cannot avoid** (for example, running a memory acquisition tool on a live host changes RAM, so write down the tool, version, time and reason).
- **Verify** integrity with cryptographic hashes (Day 2): hash at acquisition, hash again before analysis, and the hashes must match.

#### The ACPO principles (UK, widely adopted)

1. No action should change data that may later be relied on in court.
2. If you *must* access original data, you must be competent to do so and able to explain the relevance and implications of your actions.
3. Keep an **audit trail** of every process applied to the evidence. An independent third party should be able to repeat the process and get the same result.
4. The person in charge of the investigation is responsible for making sure the law and these principles are followed.

#### Chain of custody

A chain of custody is a written, unbroken record of **who** handled the evidence, **what** they did with it, **when**, **where** and **why**, from seizure until it is disposed of. A minimal record looks like this:

| Field | Example |
|-------|---------|
| Case ID / Evidence ID | CASE-2026-001 / EV-003 |
| Description | Samsung 1 TB SSD, S/N S6XXNJ0R123456, removed from laptop HOST-FIN-07 |
| Collected by / date-time (UTC) | A. Analyst, 2026-09-28 09:14 UTC |
| Hash at acquisition (SHA-256) | `9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08` |
| Transfers | Released by → Received by, date/time, purpose, signatures |
| Storage location | Evidence locker 2, shelf B, sealed bag #00412 |

You'll build a proper chain-of-custody form tomorrow (Day 2).

#### Documentation and time

- Keep **contemporaneous notes**: what you did, when, with which tool and version, and what you saw. If it isn't written down, it didn't happen.
- **Work in UTC.** Set your analysis machines to UTC and record the suspect system's time-zone setting. Time-zone mistakes are among the most common errors in timelines.
- Note **clock skew**: compare the suspect system's clock to a trusted time source when you seize it.

### 1.7 Legal and ethical foundations

- **Authorisation first.** You need legal authority before you touch anything: a warrant, a court order, written consent, or a corporate policy plus an engagement letter. Stay inside the agreed **scope**.
- **Privacy.** Evidence often contains personal data (GDPR, HIPAA, local privacy law). Access only what the scope requires.
- **Admissibility** generally needs evidence that is **relevant, authentic, reliable, and complete**. Examples by jurisdiction:
  - 🇺🇸 US: Federal Rules of Evidence 901/902 (FRE 902(14) allows electronic copies to be self-authenticated by hash); the *Daubert* standard for expert testimony.
  - 🇬🇧 UK: ACPO Good Practice Guide for Digital Evidence; the Forensic Science Regulator's statutory Code of Practice.
  - 🇮🇳 India: Bharatiya Sakshya Adhiniyam 2023 (Section 63 certificate for electronic records, replacing the old Evidence Act Section 65B).
- **International standards:** ISO/IEC **27037** (identification, collection, acquisition, preservation), **27041** (assurance of methods), **27042** (analysis and interpretation), **27043** (investigation principles and processes).

> ⚠️ This course is for learning and authorised investigations only. Practise on your own machines, on lab VMs, and on the public datasets listed in §1.9.

### 1.8 The analyst mindset

- **Be hypothesis-driven.** Form a theory ("the attacker used RDP from the VPN pool") and try to *disprove* it with evidence.
- **Corroborate.** One artifact is a clue; three independent artifacts pointing the same way are a finding. For example, Prefetch + Amcache + Event ID 4688 all showing that `evil.exe` executed.
- **Absence of evidence is not evidence of absence.** Logs may have rolled over, been disabled or been cleared.
- **Watch for confirmation bias.** Write down the evidence that *contradicts* your theory too.
- **Validate your tools.** Tools have bugs. Test them on known data (the lab in Part 3 does exactly that) and cross-check important findings with a second tool.
- **Report facts, then opinions.** Say clearly which is which, and how confident you are.

### 1.9 Designing your DFIR lab

#### Hardware

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 4 cores with VT-x/AMD-V | 8+ cores |
| RAM | 16 GB | 32–64 GB (memory analysis and Plaso are RAM-hungry) |
| System disk | 512 GB SSD | 1 TB NVMe |
| Evidence/case storage | 1 TB external | Separate 2–4 TB SSD/HDD dedicated to cases |
| Extras | | Hardware write-blocker (e.g., Tableau/WiebeTech), USB 3 docks, SATA/NVMe adapters |

#### Virtualisation (pick one)

- **VMware Workstation Pro / Fusion Pro**: free for personal *and* commercial use since November 2024 (download from the Broadcom support portal).
- **Oracle VirtualBox 7.x**: free and cross-platform.
- **Hyper-V** (Windows Pro/Enterprise), **UTM / Parallels** (Apple silicon: use ARM64 guests).

#### Lab layout

```
                    ┌───────────────────────── Host (your PC) ─────────────────────────┐
                    │                                                                  │
                    │  ┌───────────────┐   ┌────────────────────┐   ┌───────────────┐  │
                    │  │ SIFT (Linux)  │   │ Windows 10/11      │   │ Malware VM    │  │
                    │  │ analysis VM   │   │ analysis VM        │   │ (REMnux/      │  │
                    │  │ Day 1         │   │ EZ Tools – Day 1   │   │ FLARE-VM)     │  │
                    │  └──────┬────────┘   └────────┬───────────┘   │ Day 42        │  │
                    │         │ host-only / NAT     │               │ NO internet   │  │
                    │         └─────────┬───────────┘               └───────────────┘  │
                    │                   │                                              │
                    │        ┌──────────▼──────────┐    ┌─────────────────────────┐    │
                    │        │ Cases share         │    │ "Victim" VMs to generate│    │
                    │        │ (evidence READ-ONLY)│    │ artifacts & practise    │    │
                    │        └─────────────────────┘    └─────────────────────────┘    │
                    └──────────────────────────────────────────────────────────────────┘
```

**Lab rules**

1. **Isolation:** analysis VMs use *host-only* or NAT networking. Malware VMs have **no** route to the internet or your home network.
2. **Snapshots:** take a "clean baseline" snapshot after each tool install, and roll back after risky work.
3. **Evidence is read-only:** mount evidence shares read-only, and write outputs to a separate `export/` folder.
4. **Antivirus exclusions (analysis VMs only):** Windows Defender *will* quarantine malware inside your evidence and break your case. Exclude your cases folder on the **Windows analysis VM**, and never on your host.
5. **Consistent case folders:**

```
Cases/
└── CASE-2026-001/
    ├── evidence/      # original images (read-only, hashed)
    ├── export/        # files extracted from evidence
    ├── output/        # tool outputs (CSV, JSON, timelines)
    ├── notes/         # contemporaneous notes, chain of custody
    └── reports/       # drafts and final report
```

#### Free practice data

| Source | What you get |
|--------|--------------|
| **NIST CFReDS**: https://cfreds.nist.gov | Reference disk, memory and mobile datasets, many with answer keys |
| **Digital Corpora**: https://digitalcorpora.org | Realistic disk images, scenarios (e.g., M57-Patents), file corpora |
| **DFIR Madness**: https://dfirmadness.com | "The Stolen Szechuan Sauce" and other full cases (disk, memory, PCAP) |
| **CyberDefenders**: https://cyberdefenders.org | Blue-team labs with questions |
| **13Cubed**: https://www.13cubed.com | Investigation challenges and excellent videos |
| **Ali Hadi's datasets**: https://www.ashemery.com/dfir.html | Windows/Linux/web-server case images |

---

## Part 2: Tools

---

### 🛠️ Tool 1: SIFT Workstation

| | |
|---|---|
| **What** | The SANS Investigative Forensic Toolkit: a free Ubuntu-based forensic workstation with hundreds of tools preinstalled (The Sleuth Kit, Plaso, Volatility 3, bulk_extractor, libewf, RegRipper and more) |
| **Why** | One consistent, well-maintained Linux analysis platform. It's used in SANS courses and in the field |
| **Platforms** | Ubuntu **22.04 (Jammy)** and **24.04 (Noble)**, `amd64` and `arm64` (a few packages are amd64-only). Available as a ready-made VM (OVA) or installed onto your own Ubuntu |
| **Licence** | Free |
| **Home** | https://www.sans.org/tools/sift-workstation · https://github.com/teamdfir/sift-saltstack |

#### Requirements

- VM with **≥ 2 vCPUs, ≥ 8 GB RAM** (4 GB minimum), **≥ 80 GB disk** (thin-provisioned).
- Internet access during installation.

#### Option A: Download the prebuilt VM (easiest)

1. Go to https://www.sans.org/tools/sift-workstation, sign in with a free SANS account and download the **OVA**.
2. **Verify the download:** compare its hash with the one on the download page.
   ```bash
   # Linux / macOS
   sha256sum SIFT-Workstation.ova        # macOS: shasum -a 256 SIFT-Workstation.ova
   ```
   ```powershell
   # Windows
   Get-FileHash .\SIFT-Workstation.ova -Algorithm SHA256
   ```
3. **Import:**
   - VMware: *File → Open…* → select the `.ova` → *Import*.
   - VirtualBox: *File → Import Appliance…*, or from the CLI:
     ```bash
     VBoxManage import SIFT-Workstation.ova --vsys 0 --vmname "SIFT" --memory 8192 --cpus 4
     ```
4. Boot and log in with the default credentials **`sansforensics` / `forensics`**, then **change the password immediately**:
   ```bash
   passwd
   ```

#### Option B: Install SIFT on your own Ubuntu 22.04/24.04 with Cast (recommended for up-to-date builds)

[Cast](https://github.com/ekristen/cast) is the official SIFT installer. It replaced the old `sift-cli`.

```bash
# 1. Start from a fresh, fully updated Ubuntu 22.04 or 24.04 (desktop or server)
sudo apt update && sudo apt -y full-upgrade
sudo reboot

# 2. Download the latest Cast .deb for your CPU architecture from:
#    https://github.com/ekristen/cast/releases
#    (amd64 for Intel/AMD, arm64 for Apple silicon / ARM)
#    then install it:
sudo dpkg -i ~/Downloads/cast*linux*amd64*.deb      # adjust the filename to what you downloaded
cast --version

# 3. Install SIFT (desktop mode = tools + SIFT desktop customisations)
sudo cast install teamdfir/sift-saltstack

#    ...or tools only, without desktop customisations (servers / headless / WSL2):
# sudo cast install --mode=server teamdfir/sift-saltstack

# 4. Reboot when it finishes (expect 30–90 minutes depending on bandwidth)
sudo reboot
```

> 💡 `sift` is a built-in alias, so `sudo cast install sift` also works.
> Cast sends anonymous version telemetry. Disable it with `export CHECKPOINT_DISABLE=1` before running `cast` (use `sudo -E` to keep the variable).

#### Post-install configuration

```bash
# 1. Work in UTC (critical for timelines)
sudo timedatectl set-timezone UTC
timedatectl

# 2. Install VM guest tools for clipboard, resizing and shared folders
sudo apt install -y open-vm-tools-desktop                      # VMware
# or, for VirtualBox:
sudo apt install -y virtualbox-guest-utils virtualbox-guest-x11
sudo usermod -aG vboxsf "$USER"                                # allow access to VirtualBox shared folders

# 3. Create your cases structure
mkdir -p ~/cases
ls /mnt          # SIFT pre-creates several mount points here for mounting images

# 4. Keep SIFT up to date: re-running the install upgrades to the latest release
sudo cast install teamdfir/sift-saltstack
```

**Share evidence into the VM read-only (VirtualBox example, run on the host):**

```bash
VBoxManage sharedfolder add "SIFT" --name cases --hostpath "/path/to/Cases" --readonly --automount
# Inside SIFT it appears under /media/sf_cases
```

**Take a snapshot now:**

```bash
VBoxManage snapshot "SIFT" take "01-clean-install" --description "SIFT fresh install, UTC, guest tools"
```

(VMware: *VM → Snapshot → Take Snapshot*.)

#### Verify the installation

```bash
fls -V                          # The Sleuth Kit
mmls -V
ewfinfo -V                      # libewf
log2timeline.py --version       # Plaso
vol -h | head -n 5              # Volatility 3 (on some builds: vol.py -h)
bulk_extractor -V
regripper -h 2>/dev/null | head -n 3 || rip.pl -h | head -n 3   # RegRipper
```

If each command prints a version or help text, you're ready.

#### Troubleshooting

| Symptom | Fix |
|---------|-----|
| `unsupported OS` / release error | Use Ubuntu 22.04 or 24.04 only (not Mint, Debian or non-LTS releases) |
| A Salt state fails partway through | Re-run the same `cast install` command; it's idempotent. Check disk space (`df -h`, need ≥ 20 GB free) and proxy/firewall settings |
| `Could not get lock /var/lib/dpkg/lock` | Wait for automatic updates to finish (`ps aux \| grep -i apt`), then retry |
| Some tool missing on arm64 | A few packages are amd64-only; use an amd64 VM for those |

---

### 🛠️ Tool 2: CyberChef

| | |
|---|---|
| **What** | "The Cyber Swiss Army Knife" from GCHQ: a web app with hundreds of operations for encoding/decoding, decryption, compression, hashing, timestamp conversion, parsing (X.509, IPv6, protobuf…), regex extraction and more. You chain operations into **recipes** |
| **Why in DFIR** | Decoding obfuscated PowerShell, Base64/hex blobs, XOR-encrypted configs, converting Windows FILETIME/Unix/Chrome timestamps, defanging and extracting IOCs, and more, all in a few clicks |
| **Platforms** | Any modern browser. Runs **entirely client-side** (your data isn't sent to a server) |
| **Licence** | Apache 2.0 |
| **Home** | https://github.com/gchq/CyberChef · public instance: https://gchq.github.io/CyberChef |

> ⚠️ **OPSEC:** The public site processes data locally, but you should still **run your own offline copy for case work**. Air-gapped labs need one anyway. Also be careful when sharing CyberChef URLs: with *"Update the URL when the input or recipe changes"* enabled, **your input data is embedded in the URL**.

#### Option A: Standalone offline HTML (recommended, works on any OS)

1. Download `CyberChef_vX.Y.Z.zip` from https://github.com/gchq/CyberChef/releases (latest release).
2. Unzip it and open `CyberChef_vX.Y.Z.html` in your browser. That's it: no server, no internet needed.

**Linux / SIFT:**

```bash
mkdir -p ~/tools/cyberchef && cd ~/tools/cyberchef
# Replace vX.Y.Z with the latest version number from the releases page
VER="vX.Y.Z"
wget "https://github.com/gchq/CyberChef/releases/download/${VER}/CyberChef_${VER}.zip"
unzip "CyberChef_${VER}.zip"
sha256sum "CyberChef_${VER}.zip"        # record the hash in your tool log

# Create a desktop launcher
cat > ~/.local/share/applications/cyberchef.desktop <<EOF
[Desktop Entry]
Name=CyberChef
Exec=xdg-open ${HOME}/tools/cyberchef/CyberChef_${VER}.html
Type=Application
Categories=Utility;
EOF
```

**Windows (PowerShell):**

```powershell
$ver = "vX.Y.Z"   # latest version from the releases page
New-Item -ItemType Directory -Path C:\Tools\CyberChef -Force | Out-Null
Invoke-WebRequest "https://github.com/gchq/CyberChef/releases/download/$ver/CyberChef_$ver.zip" -OutFile "C:\Tools\CyberChef\CyberChef.zip"
Expand-Archive C:\Tools\CyberChef\CyberChef.zip -DestinationPath C:\Tools\CyberChef -Force
Start-Process "C:\Tools\CyberChef\CyberChef_$ver.html"
```

#### Option B: Docker (share one instance with your team or lab)

```bash
# Pre-built image published by GCHQ; bound to localhost only
docker run -d --name cyberchef --restart unless-stopped \
  -p 127.0.0.1:8080:8080 ghcr.io/gchq/cyberchef:latest
# Browse to http://localhost:8080
```

To expose it to a lab network, change `127.0.0.1:8080` to `<lab-ip>:8080`. Put it behind authentication if other people can reach it.

#### Option C: From source (for developers adding operations)

Requires **Node.js v24**:

```bash
git clone https://github.com/gchq/CyberChef.git && cd CyberChef
npm install
npm start          # dev server at http://localhost:8080
npm run build      # production build in build/prod
```

#### Configuration tips

Open **Options** (⚙️, top right):

- **Auto Bake:** turn it **off** for large inputs (multi-MB logs) and press **BAKE!** manually.
- **Attempt to detect encoded data automagically:** keep it on. The 🪄 *magic wand* in the output pane suggests decodings.
- **Update the URL when the input or recipe changes:** consider turning it **off** so case data doesn't end up in your browser history.
- **Word wrap / Theme:** set to taste (a dark theme is easier on the eyes for long sessions).
- **Save recipes** (💾 in the Recipe pane) to local storage, or export them as JSON and keep a team recipe library in Git.

#### Verify

Type `hello` into the Input pane, add **To Base64** to the recipe, and the output should be `aGVsbG8=`.

---

### 🛠️ Tool 3: Eric Zimmerman's Tools (EZ Tools)

| | |
|---|---|
| **What** | A free suite of Windows artifact parsers by Eric Zimmerman. It includes **MFTECmd, PECmd, LECmd, JLECmd, RECmd, Registry Explorer, EvtxECmd, AmcacheParser, AppCompatCacheParser, SrumECmd, SBECmd/ShellBags Explorer, RBCmd, WxTCmd, SQLECmd, bstrings, Hasher, Timeline Explorer** and more |
| **Why** | The de-facto standard for Windows artifact analysis: fast, accurate, CSV/JSON output, and the parsers behind many KAPE modules. You'll use them throughout Phase 2 |
| **Platforms** | Windows 10/11 x64 (analysis VM). Builds target **.NET 9** (default since May 2025); legacy .NET 4 builds are also available |
| **Licence** | Free (most tools are MIT open source) |
| **Home** | https://ericzimmerman.github.io · https://github.com/EricZimmerman |

#### Requirements

- A **Windows 10/11 analysis VM** (≥ 4 vCPUs, ≥ 8 GB RAM, 100 GB disk). The free 90-day **Windows 11 Enterprise evaluation** ISO from the Microsoft Evaluation Center is fine for a lab.
- **.NET 9 Desktop Runtime** (x64). It also includes the base .NET runtime and is needed by the GUI tools.

#### Step 1: Install the .NET 9 runtime

```powershell
# Using winget (Windows 10 1809+ / Windows 11)
winget install --id Microsoft.DotNet.DesktopRuntime.9 -e --accept-source-agreements --accept-package-agreements

# Verify: expect Microsoft.NETCore.App 9.x and Microsoft.WindowsDesktop.App 9.x
dotnet --list-runtimes
```

No winget? Download "**.NET Desktop Runtime 9.x (x64)**" from https://dotnet.microsoft.com/download/dotnet/9.0 and install it.

#### Step 2: Download all tools with Get-ZimmermanTools

Run **PowerShell as Administrator**:

```powershell
# Create a tools folder
New-Item -ItemType Directory -Path C:\Tools\ZimmermanTools -Force | Out-Null
Set-Location C:\Tools\ZimmermanTools

# Download and unpack the updater script
Invoke-WebRequest -Uri "https://download.ericzimmermanstools.com/Get-ZimmermanTools.zip" -OutFile Get-ZimmermanTools.zip
Expand-Archive .\Get-ZimmermanTools.zip -DestinationPath . -Force
Unblock-File .\Get-ZimmermanTools.ps1

# Allow scripts for this session only, then fetch all .NET 9 builds
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\Get-ZimmermanTools.ps1 -Dest C:\Tools\ZimmermanTools -NetVersion 9 -Sync
```

What the parameters do:

| Parameter | Meaning |
|-----------|---------|
| `-Dest` | Where to save the tools |
| `-NetVersion` | `9` = .NET 9 builds (default), `4` = legacy .NET 4 builds, `0` = everything |
| `-Sync` | Also runs `--sync` for **EvtxECmd, RECmd and SQLECmd** to pull the latest community **maps and batch files** (important!) |
| `-Proxy`, `-ProxyCredential`, `-ProxyUseDefaultCredentials` | For corporate networks behind a proxy |

**Where things land:** .NET 9 builds go into `C:\Tools\ZimmermanTools\net9\`. Simple CLI tools (e.g., `PECmd.exe`, `LECmd.exe`) sit directly in that folder. Tools with support files (EvtxECmd, RECmd, SQLECmd) and GUI tools (Timeline Explorer, Registry Explorer, ShellBags Explorer) get their own sub-folders. To list everything:

```powershell
Get-ChildItem C:\Tools\ZimmermanTools\net9 -Recurse -Filter *.exe | Select-Object FullName
```

The script also writes `!!!RemoteFileDetails.csv`, which tracks file hashes so that **re-running the script only downloads tools that changed**.

#### Step 3: Configure

**Add the tools to your PATH** so you can call them from any prompt:

```powershell
$ez = 'C:\Tools\ZimmermanTools\net9'
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
[Environment]::SetEnvironmentVariable('Path', "$userPath;$ez;$ez\EvtxECmd;$ez\RECmd;$ez\SQLECmd", 'User')
# Open a new PowerShell window for the change to take effect
```

**Exclude your cases folder from Defender** (analysis VM only, as explained in §1.9):

```powershell
New-Item -ItemType Directory -Path C:\Cases -Force | Out-Null
Add-MpPreference -ExclusionPath 'C:\Cases'
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
```

**Set the VM to UTC:**

```powershell
Set-TimeZone -Id "UTC"
Get-TimeZone
```

**Keep the tools updated** (run weekly):

```powershell
C:\Tools\ZimmermanTools\Get-ZimmermanTools.ps1 -Dest C:\Tools\ZimmermanTools -NetVersion 9 -Sync
```

Take a VM snapshot: **"02-EZTools-installed"**.

#### Verify

```powershell
PECmd.exe --help | Select-Object -First 5      # prints version and usage
MFTECmd.exe --help | Select-Object -First 5
EvtxECmd.exe --help | Select-Object -First 5
Get-ChildItem C:\Tools\ZimmermanTools\net9\EvtxECmd\Maps | Measure-Object   # should be hundreds of maps
```

Then launch **Timeline Explorer** (`...\net9\TimelineExplorer\TimelineExplorer.exe`). If the window opens, the Desktop Runtime is installed correctly.

#### Troubleshooting

| Symptom | Fix |
|---------|-----|
| "You must install .NET to run this application" | Install the **.NET 9 Desktop Runtime x64** (not just the ASP.NET runtime) |
| Script blocked / "not digitally signed" | `Unblock-File` it and use `Set-ExecutionPolicy -Scope Process Bypass` |
| Downloads fail on a corporate network | Use `-Proxy http://proxy:8080 -ProxyUseDefaultCredentials` |
| Defender deletes a tool or an output file | Add an exclusion for `C:\Tools` too (analysis VM only) |

---

## Part 3: Hands-on labs

### Lab 1: Set up your first case (5 min)

On **SIFT**:

```bash
CASE=~/cases/LAB-001
mkdir -p $CASE/{evidence,export,output,notes,reports}
cat > $CASE/notes/case-notes.md <<'EOF'
# Case LAB-001: Notes
Examiner: <your name>
Timezone of analysis system: UTC

| Time (UTC) | Action | Tool / version | Result / observation |
|------------|--------|----------------|----------------------|
EOF
echo "| $(date -u +'%F %T') | Created case structure | bash | OK |" >> $CASE/notes/case-notes.md
cat $CASE/notes/case-notes.md
```

Get into the habit: **every action goes in the notes**.

### Lab 2: Recover your first deleted file (20 min) on SIFT

You'll create a small USB-stick-like disk image, put two files on it, delete one, and then recover the deleted file forensically.

```bash
cd ~/cases/LAB-001/evidence
sudo apt install -y dosfstools mtools        # usually already present

# 1. Create a 32 MB blank "USB stick" and format it FAT16
dd if=/dev/zero of=usb-sim.img bs=1M count=32 status=progress
mkfs.vfat -F 16 -n EVIDENCE usb-sim.img

# 2. "Suspect activity": write two files, then delete one
echo "Meet at the docks at 23:00" > /tmp/secret-plan.txt
echo "Grocery list: milk, eggs"   > /tmp/notes.txt
mcopy -i usb-sim.img /tmp/secret-plan.txt /tmp/notes.txt ::/
mdel  -i usb-sim.img ::/secret-plan.txt
rm /tmp/secret-plan.txt /tmp/notes.txt

# 3. Preserve: hash it, then make it read-only
sha256sum usb-sim.img | tee ../notes/usb-sim.img.sha256
chmod 444 usb-sim.img

# 4. Examine with The Sleuth Kit
fsstat usb-sim.img | head -n 12        # file system details (FAT16, label EVIDENCE)
fls -r usb-sim.img                     # list files; deleted entries are marked with '*'
```

Expected output (the entry numbers may differ):

```
r/r 3:     EVIDENCE    (Volume Label Entry)
r/r * 6:   secret-plan.txt        <-- '*' = deleted
r/r 7:     notes.txt
...
```

```bash
# 5. Inspect and recover the deleted file using its entry number (6 above)
istat usb-sim.img 6                                   # metadata: "Not Allocated", size, timestamps
icat  usb-sim.img 6 > ../export/recovered-secret-plan.txt
cat ../export/recovered-secret-plan.txt               # -> Meet at the docks at 23:00

# 6. Prove you didn't change the evidence
sha256sum -c ../notes/usb-sim.img.sha256              # -> usb-sim.img: OK
```

🔍 **Look closely at `istat`:** the short (8.3) name shows as **`_ECRET~1.TXT`**. When FAT deletes a file it overwrites the **first byte of the directory entry with `0xE5`**. The data and the rest of the entry stay until they are overwritten. That's why the long file name survived but the short name lost its first letter. You'll learn exactly why on Day 4 (file systems) and Day 7 (carving).

Log each step in `case-notes.md`.

### Lab 3: CyberChef decoding (10 min)

1. **Encoded PowerShell.** Attackers use `powershell -EncodedCommand <base64>`, where the Base64 wraps **UTF-16LE** text. Paste this into the Input pane:
   ```
   VwByAGkAdABlAC0ASABvAHMAdAAgACIASABlAGwAbABvACAAZgByAG8AbQAgAEQAYQB5ACAAMQAgAG8AZgAgAEQARgBJAFIAIgA=
   ```
   Recipe: **From Base64** → **Decode text** (encoding `UTF-16LE (1200)`).
   ✅ Expected: `Write-Host "Hello from Day 1 of DFIR"`

   *(Try the 🪄 magic wand as well and see whether it finds the decoding on its own.)*

2. **Windows FILETIME.** Many Windows artifacts store timestamps as FILETIME: the number of 100-nanosecond intervals since 1601-01-01 UTC. Input:
   ```
   133700000000000000
   ```
   Recipe: **Windows Filetime to UNIX Timestamp** (output units: Seconds, input format: Decimal) → **From UNIX Timestamp** (units: Seconds).
   ✅ Expected: `Thu 5 September 2024 08:53:20 UTC`

   💡 In a hex editor the same value appears **little-endian** as `00 40 78 0E 71 FF DA 01`. Reverse the byte order before converting.

3. Save the first recipe as **"PS EncodedCommand"**. You'll reuse it often.

### Lab 4: EZ Tools first run (10 min) on the Windows VM

Parse your **own analysis VM's** Prefetch files. This is safe practice data; in real cases you'll parse *collected copies* (Day 9).

```powershell
# PowerShell as Administrator (Prefetch needs admin rights)
New-Item -ItemType Directory -Path C:\Cases\LAB-001\output -Force | Out-Null
PECmd.exe -d C:\Windows\Prefetch --csv C:\Cases\LAB-001\output --csvf prefetch.csv
```

Open `C:\Cases\LAB-001\output\prefetch.csv` in **Timeline Explorer**. Try these:

- Sort by **Last Run**. What executed most recently?
- Filter **Executable Name** for `POWERSHELL.EXE`. How many times has it run (**Run Count**)?
- Look at the **Files Loaded** column for one entry. This is how Prefetch reveals files and DLLs touched by a program (Day 12).

---

## ✅ Knowledge check

1. Name the six stages of the generic forensic process.
2. According to RFC 3227, should you image the disk or capture RAM first on a running system? Why?
3. What does Locard's Exchange Principle mean for *you* as an examiner?
4. Give three fields every chain-of-custody record must contain.
5. Why should analysis workstations be set to UTC?
6. Why must you exclude your cases folder from antivirus on the Windows analysis VM, and why never on your host?
7. In Lab 2, why did the deleted file's short name become `_ECRET~1.TXT`?
8. Which `Get-ZimmermanTools.ps1` switch pulls the latest EvtxECmd/RECmd/SQLECmd maps?

<details>
<summary><b>Answers</b></summary>

1. Identification → Preservation → Collection → Examination → Analysis → Reporting.
2. RAM first: it's far more volatile, and imaging the disk takes time while RAM contents (processes, connections, keys) keep changing or disappear.
3. Your own actions leave traces and can overwrite evidence. Minimise interaction with originals and document everything you do.
4. Any three of: evidence ID/description, who handled it, date/time of each transfer, purpose, location, hash values, signatures.
5. It avoids time-zone conversion errors when you correlate artifacts from different systems and log sources.
6. Defender would quarantine or delete malware inside evidence and outputs, which alters your case data. On your host, the exclusion would weaken your real protection.
7. On deletion, FAT overwrites the first byte of the short-name directory entry with `0xE5`. TSK shows that byte as `_`.
8. `-Sync`.

</details>

---

## 📚 Further reading

- NIST SP 800-86: *Guide to Integrating Forensic Techniques into Incident Response*
- NIST SP 800-61 Rev. 3: *Incident Response Recommendations and Considerations for Cybersecurity Risk Management* (2025)
- RFC 3227: *Guidelines for Evidence Collection and Archiving*
- ACPO *Good Practice Guide for Digital Evidence* (v5)
- SANS DFIR posters: *Windows Forensic Analysis*, *Hunt Evil* (free at sans.org/posters)
- Brian Carrier, *File System Forensic Analysis*: the classic reference for Days 3–7
- Community: **This Week in 4n6** (weekly news), **AboutDFIR.com**, **DFIR.training**, **13Cubed** (YouTube)

---

## ⏭️ Tomorrow: Day 02

**Evidence handling, chain of custody, integrity & hashing**. Tools: **hashdeep**, **ssdeep**, **HashMyFiles**.
We'll build a real chain-of-custody form, hash a whole evidence set, audit it for tampering, and use fuzzy hashing to find "similar" files.

---

<sub>Part of the <a href="../README.md">DFIR Daily</a> series · <a href="../CURRICULUM.md">Full 60-day curriculum</a> · For educational and authorised use only.</sub>
