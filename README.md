# DFIR: Digital Forensics & Incident Response

**Learn to investigate cyber incidents, from the basics to advanced practice: find the evidence, understand what happened, and prove it.**

![Updated daily](https://img.shields.io/badge/updated-daily-2ea44f)
![60 lessons](https://img.shields.io/badge/lessons-60-blue)
![180 tools](https://img.shields.io/badge/tools-180-orange)
![Beginner to Advanced](https://img.shields.io/badge/level-beginner%20%E2%86%92%20advanced-purple)

DFIR is the work of collecting and analysing digital evidence (disks, memory, network traffic, logs, phones and cloud accounts) to answer **what happened, when, how, and who was involved**. This repo is a free, hands-on course that teaches it one day at a time.

## 📅 DFIR Daily

A new lesson is posted **every day**. Each one covers:

- **📖 The lesson:** concepts, artifacts and investigation methods for the day's topic, from the basics up to advanced practitioner level.
- **🛠️ 3 tools per day:** what each tool is, how to **install** it (Linux / Windows / macOS / Docker), how to **configure** it, how to **check the install**, a first hands-on use, and troubleshooting.
- **🧪 Hands-on labs** with expected output, a **✅ knowledge check** and **📚 further reading**.

➡️ See the full **[60-day curriculum](CURRICULUM.md)** (10 phases: Foundations → Windows → Memory → Network → Linux → macOS → Mobile → Malware → IR & Threat Hunting → Cloud & Automation).

## 📚 Lessons

| Day | Date | Topic | Tools | Level |
|----:|------|-------|-------|:-----:|
| 01 | 2026-09-28 | [Introduction to Digital Forensics & Building Your DFIR Lab](days/day-01-intro-to-dfir-and-lab-setup.md) | SIFT Workstation · CyberChef · Eric Zimmerman's Tools | 🟢 |
| 02 | 2026-09-29 | [Evidence Handling, Chain of Custody, Integrity & Hashing](days/day-02-evidence-handling-chain-of-custody-hashing.md) | hashdeep · ssdeep · HashMyFiles | 🟢 |
| 03 | 2026-09-30 | [Storage Media, Partitions (MBR/GPT), Hex & File Signatures](days/day-03-storage-partitions-hex-file-signatures.md) | HxD · ImHex · TestDisk | 🟢 |
| 04 | 2026-10-01 | [File System Fundamentals: FAT/exFAT, NTFS, ext4, APFS & MACB Timestamps](days/day-04-file-system-fundamentals-and-timestamps.md) | The Sleuth Kit · Autopsy · fatcat | 🟢→🟡 |
| 05 | 2026-10-02 | [Disk Acquisition: Physical vs Logical, Write Blocking & Image Formats](days/day-05-disk-acquisition-write-blocking-image-formats.md) | FTK Imager · Guymager · dc3dd | 🟢→🟡 |
| 06 | 2026-10-03 | [Forensic Image Formats, Verification & Mounting Images Safely](days/day-06-image-formats-verification-and-mounting.md) | libewf (ewf-tools) · Arsenal Image Mounter · xmount | 🟡 |
| 07 | 2026-10-04 | [Data Recovery & File Carving](days/day-07-data-recovery-and-file-carving.md) | PhotoRec · Foremost · Scalpel | 🟡 |
<!-- NEXT-DAY-ROW -->

Legend: 🟢 Beginner · 🟡 Intermediate · 🔴 Advanced

## 🧭 How to use this repo

1. Start at **Day 01** and build the lab. Every later lesson assumes you have the SIFT (Linux) and Windows analysis VMs.
2. Do the labs, and keep **case notes** for every exercise. That habit matters as much as the tools.
3. Check your answers with the knowledge check at the end of each day.

## ⚖️ Disclaimer

For educational purposes and **authorised** investigations only. Practise on systems you own, on lab VMs, or on public forensic datasets.
