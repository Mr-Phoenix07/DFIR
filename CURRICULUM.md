# DFIR Daily — 60-Day Curriculum (Basic → Advanced)

One lesson per day. Every lesson has two halves:

1. **The lesson**: the concepts, artifacts and methods for the day's topic.
2. **Three tools**: for each one, what it is, how to install it (Linux / Windows / macOS where supported), how to configure it, how to check the install worked, and a first hands-on use.

Each lesson finishes with a hands-on lab, a knowledge check and further reading.

Legend: 🟢 Beginner · 🟡 Intermediate · 🔴 Advanced

---

## Phase 1 — Foundations (Days 1–8) 🟢

| Day | Topic | Tools |
|----:|-------|-------|
| 01 | Introduction to Digital Forensics & DFIR, the forensic process, core principles, building your lab | SIFT Workstation · CyberChef · Eric Zimmerman's Tools |
| 02 | Evidence handling, chain of custody, integrity & hashing | hashdeep · ssdeep · HashMyFiles |
| 03 | Storage media, partitions (MBR/GPT), sectors, hex & file signatures | HxD · ImHex · TestDisk |
| 04 | File system fundamentals: FAT/exFAT, NTFS, ext4, APFS, timestamps (MACB) | The Sleuth Kit · Autopsy · fatcat |
| 05 | Disk acquisition: physical vs logical, write blockers, raw/E01/AFF4 | FTK Imager · Guymager · dc3dd |
| 06 | Forensic image formats, verification & mounting images | libewf (ewf-tools) · Arsenal Image Mounter · xmount |
| 07 | Data recovery & file carving | PhotoRec · Foremost · Scalpel |
| 08 | Metadata, file-type identification & bulk feature extraction | ExifTool · TrID · bulk_extractor |

## Phase 2 — Windows Forensics (Days 9–22) 🟢→🟡

| Day | Topic | Tools |
|----:|-------|-------|
| 09 | Windows triage collection | KAPE · AChoirX¹ · DFIR ORC |
| 10 | NTFS deep dive: $MFT, $UsnJrnl:$J, $LogFile, $I30 | MFTECmd · NTFS Log Tracker · analyzeMFT |
| 11 | Windows Registry fundamentals: hives, keys, transaction logs | Registry Explorer · RECmd · RegRipper |
| 12 | Evidence of execution: Prefetch, Amcache, Shimcache, BAM/DAM | PECmd · AmcacheParser · AppCompatCacheParser |
| 13 | File & folder knowledge: LNK, Jump Lists, ShellBags | LECmd · JLECmd · ShellBags Explorer (SBECmd) |
| 14 | Windows Event Logs: EVTX structure & key event IDs | EvtxECmd · evtx_dump · FullEventLogView |
| 15 | Event-log threat hunting with Sigma rules | Hayabusa · Chainsaw · DeepBlueCLI |
| 16 | Sysmon & enhanced logging for investigators | Sysmon · sigma-cli (pySigma) · Zircolite |
| 17 | SRUM, Recycle Bin & Windows Timeline (ActivitiesCache) | SrumECmd · RBCmd · WxTCmd |
| 18 | Browser forensics: Chromium, Firefox, Edge | Hindsight · BrowsingHistoryView · DB Browser for SQLite |
| 19 | Email forensics: PST/OST, EML/MSG, header analysis | libpff (pffexport) · readpst · eml_analyzer |
| 20 | Volume Shadow Copies & BitLocker volumes | libvshadow · dislocker · ShadowExplorer |
| 21 | Super timelines: building and analysing | Plaso (log2timeline) · Timeline Explorer · Timesketch |
| 22 | Windows persistence hunting | Autoruns · PersistenceSniper · Trawler |

## Phase 3 — Memory Forensics (Days 23–27) 🟡

| Day | Topic | Tools |
|----:|-------|-------|
| 23 | Memory forensics fundamentals & Windows RAM acquisition | WinPmem · Magnet RAM Capture · Belkasoft Live RAM Capturer |
| 24 | Memory analysis essentials: processes, DLLs, handles, network | Volatility 3 · Volatility Workbench · MemProcFS |
| 25 | Hunting malicious code in memory: injection, hollowing, shellcode | YARA · PE-sieve / HollowsHunter · Moneta |
| 26 | Linux & macOS memory acquisition and symbol tables | LiME · AVML · dwarf2json |
| 27 | Hibernation files, pagefile & crash dumps | Hibernation Recon · bstrings · WinDbg |

## Phase 4 — Network Forensics (Days 28–32) 🟡

| Day | Topic | Tools |
|----:|-------|-------|
| 28 | Network forensics fundamentals & packet capture | tcpdump · Wireshark · NetworkMiner |
| 29 | Network security monitoring: logs, alerts & beacon detection | Zeek · Suricata · RITA |
| 30 | Working with PCAP at scale | Arkime · Zui · Malcolm |
| 31 | Encrypted traffic: TLS, fingerprints (JA3/JA4) & decryption | mitmproxy · JA4+ · PolarProxy |
| 32 | Flow data & NetFlow/IPFIX analysis | nfdump · SiLK · softflowd |

## Phase 5 — Linux Forensics (Days 33–36) 🟡

| Day | Topic | Tools |
|----:|-------|-------|
| 33 | Linux forensics fundamentals & live triage collection | UAC · Cat-Scale · Fennec |
| 34 | Linux logging & auditing: journald, auth logs, auditd | auditd · LAUREL · Sysmon for Linux |
| 35 | ext4 internals, deleted files & rootkit detection | debugfs (e2fsprogs) · chkrootkit · rkhunter |
| 36 | Linux compromise hunting & runtime detection | Falco · unhide · ClamAV |

## Phase 6 — macOS Forensics (Days 37–38) 🟡

| Day | Topic | Tools |
|----:|-------|-------|
| 37 | macOS fundamentals: APFS, plists, Unified Logs, FSEvents | mac_apt · macos-UnifiedLogs · FSEventsParser |
| 38 | macOS triage & persistence | Aftermath · KnockKnock · APOLLO |

## Phase 7 — Mobile Forensics (Days 39–41) 🟡→🔴

| Day | Topic | Tools |
|----:|-------|-------|
| 39 | Android forensics: acquisition & artifact parsing | Android Platform Tools (adb) · ALEAPP · Android Triage |
| 40 | iOS forensics: backups, sysdiagnose & spyware checks | libimobiledevice · iLEAPP · MVT (Mobile Verification Toolkit) |
| 41 | App databases, plists & deleted SQLite record recovery | FQLite · SQLite Deleted Records Parser · libplist (plistutil) |

## Phase 8 — Malware Analysis for DFIR (Days 42–47) 🔴

| Day | Topic | Tools |
|----:|-------|-------|
| 42 | Building a safe malware lab & static triage | REMnux · FLARE-VM · PeStudio |
| 43 | PE analysis, packers & capability detection | Detect It Easy · capa · FLOSS |
| 44 | Malicious documents, PDFs & scripts | oletools · pdfid / pdf-parser · box-js |
| 45 | Dynamic analysis & sandboxing | CAPEv2 · INetSim · Process Monitor |
| 46 | Reverse engineering basics | Ghidra · x64dbg · dnSpyEx |
| 47 | YARA rule writing & IOC scanning | YARA-X · LOKI · THOR Lite |

## Phase 9 — Incident Response & Threat Hunting (Days 48–54) 🔴

| Day | Topic | Tools |
|----:|-------|-------|
| 48 | Live response on Windows hosts | Sysinternals Suite · System Informer · LastActivityView |
| 49 | Enterprise DFIR at scale (remote collection & hunting) | Velociraptor · GRR Rapid Response · osquery |
| 50 | Case management & collaboration | DFIR-IRIS · TheHive · Cortex |
| 51 | Threat intelligence for investigators | MISP · OpenCTI · IntelOwl |
| 52 | Log analytics & SIEM for investigations | Elastic Stack · Splunk (Free) · Wazuh |
| 53 | Threat hunting with MITRE ATT&CK | ATT&CK Navigator · DeTT&CT · Atomic Red Team |
| 54 | Anti-forensics: timestomping, log clearing, wiping & how to catch them | dfir_ntfs · INDXRipper · EVTXtract |

## Phase 10 — Cloud, Containers, Automation & Reporting (Days 55–60) 🔴

| Day | Topic | Tools |
|----:|-------|-------|
| 55 | AWS forensics: CloudTrail, snapshots & IR | AWS CLI · Prowler · SOF-ELK |
| 56 | Microsoft 365 & Entra ID investigations | Microsoft-Extractor-Suite · Hawk · CrowdStrike Reporting Tool for Azure (CRT) |
| 57 | Azure & Google Cloud investigations | Azure CLI · Google Cloud CLI (gcloud) · ScoutSuite |
| 58 | Container & Kubernetes forensics | docker-explorer · container-explorer · Sysdig (sysdig + Sysdig Inspect) |
| 59 | Automating DFIR pipelines | dfVFS · Turbinia · dfTimewolf |
| 60 | Reporting, capstone investigation & next steps | Aurora Incident Response · Dradis CE · Pandoc |

---

> The schedule may be adjusted slightly as tools change (for example a tool is deprecated or replaced).
> Any change is noted in the day's post.

### Tool changes

1. **Day 09:** CyLR → **AChoirX**. CyLR has had no commits since 2021-10-12 and targets .NET Core 3.1, which reached end of life in December 2022. AChoirX is actively maintained (v10.01.85, May 2026) and cross-platform.
