# Day 25: Hunting Malicious Code in Memory — Injection, Hollowing, Shellcode

> **Phase 3: Memory Forensics** · **Level:** 🔴 Advanced · **Time:** ~4 hours (reading + labs) · **Posted:** 2026-10-22
>
> **Tools today:** 🛠️ YARA · 🛠️ PE-sieve / HollowsHunter · 🛠️ Moneta

---

## 🎯 Learning objectives

By the end of today you will be able to:

1. Describe the main **code-injection** techniques — classic/reflective DLL injection, process hollowing, doppelgänging, thread hijacking and loose shellcode — and what each leaves in memory.
2. Explain the memory **anomalies** that give injection away: private+executable regions, unbacked `+x` memory, image/header mismatches, and missing loader links.
3. Write and run **YARA** rules over a memory dump (and a live process), reading matches by offset.
4. Use **PE-sieve** to scan one process and **HollowsHunter** to sweep them all, and **Moneta** to flag memory IOCs — and dump the implant for analysis.
5. Treat a signature hit as a **lead**: confirm the region, the process and whether code belongs there before calling it malicious.

---

## Part 1: The lesson

Day 24 listed what ran and what each process loaded. But the most capable malware doesn't run as its own process at all — it **lives inside a legitimate one**, so `pslist` shows only `explorer.exe` or `svchost.exe` behaving normally. Today you hunt the code hiding *inside* a process: the injected region, the hollowed image, the stray shellcode.

### 1.1 How code gets inside another process

A handful of techniques recur, and each leaves a different fingerprint:

- **Classic DLL injection** — `VirtualAllocEx` + `WriteProcessMemory` a DLL path into the target, then `CreateRemoteThread` → `LoadLibrary`. The DLL **is** on disk and **is** a loaded module, so it's the easiest to spot (odd module in `dlllist`).
- **Reflective DLL injection** — the payload maps *itself* from a buffer (a `ReflectiveLoader` export), never calling `LoadLibrary`. There's **no loaded-module entry** and often **no file** — `dlllist` misses it.
- **Process hollowing (RunPE)** — start a legitimate process **suspended**, `NtUnmapViewOfSection` its real image, write a malicious PE into that space, fix the entry point, resume. The process name and path look legit; the **image in memory doesn't match the file on disk**.
- **Process doppelgänging / transacted hollowing** — use NTFS transactions (or section tricks) so the on-disk file never shows the payload; the memory image is what matters.
- **Thread hijacking / APC injection** — no new thread; hijack an existing one (or queue an APC) to run shellcode already written into the process.
- **Loose shellcode** — a `+x` private allocation holding position-independent code (a Cobalt Strike beacon, a Meterpreter stage), with no PE structure at all.

### 1.2 What betrays them in memory

You rarely see the injection happen; you see its **residue**. The high-value anomalies:

- **Private + executable memory.** Normal code lives in **image**-backed regions (mapped from a DLL/EXE on disk). A **private** region (not file-backed) that is **executable** is abnormal — it's where injected shellcode and manually-mapped PEs live. This is the single strongest signal, and what `malfind` (Day 24), PE-sieve and Moneta key on.
- **Unbacked `+x` / "no image" regions.** Executable memory with no module behind it → reflective/manual mapping.
- **Image mismatch.** The bytes mapped for `notepad.exe` don't match `C:\Windows\...\notepad.exe` on disk → hollowing. PE-sieve compares the in-memory image to the file and reports the difference.
- **Header/loader anomalies.** A PE whose headers were wiped (headerless module), or a module present in the VAD tree but **missing from the PEB loader lists** (`ldrmodules` mismatch).
- **Signatures.** Shellcode has recognisable shapes — the x86 **"block API" stub** (`cld; call; pushad; mov ebp,esp; PEB walk`), egg-hunters, API-hashing loops — and payloads reference the injection **API set** (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `NtUnmapViewOfSection`). That's where **YARA** comes in.

### 1.3 Two ways to hunt: structure and signature

- **Structure-aware scanners** (PE-sieve, Moneta, Volatility `malfind`) reason about *regions*: is this memory private, executable, image-backed, consistent with disk? They find injection **by its memory properties**, even for code they've never seen.
- **Signature scanners** (YARA) match *bytes and strings*: a shellcode prologue, a loader export name, a family's constants, a C2 string. They find **known shapes** anywhere — a dump, a file, a live process — and are only as good as the rules.

They're complementary: structure finds the suspicious *region*, signatures tell you *what it is*. In practice you run `malfind`/PE-sieve to locate unbacked `+x` memory, **dump** it, then YARA it against your rule set — and YARA can also sweep the whole dump directly (and, inside Volatility, per-VAD with `windows.vadyarascan`).

### 1.4 Pitfalls

- **Generic rules over-match.** Every real PE has an `MZ`, a `PE\0\0` and the DOS stub; JIT engines (.NET, Java, browsers) legitimately make **private +x** memory. A hit is a **lead** — confirm the owning process and whether that region should hold code.
- **Legitimate reflective loaders exist.** Some EDR and packers map images manually; don't assume malice from the technique alone.
- **Smear and partial regions** (Day 23) can truncate a scanned region; corroborate.
- **Live scanning disturbs the target** (Day 23's observer effect) — prefer scanning an acquired dump when you can, and document live scans.

Today's labs run **YARA for real** on a crafted dump carrying these artifacts; PE-sieve, HollowsHunter and Moneta are **Windows-only live-process tools** (documented, not run here), so Part 2 gives their exact commands for when you have a host.

---

## Part 2: Tools

**YARA** is cross-platform and we run it below. **PE-sieve** and **HollowsHunter** are Windows and scan **live processes** (a dump isn't their input); **Moneta** is a Windows x64 live scanner. They're documented for a real host; `VER` is the version you download.

### 🛠️ Tool 1: YARA

| | |
|---|---|
| **What** | The pattern-matching engine for classifying files, memory and processes by rules (strings, byte patterns, conditions). |
| **Why** | Runs anywhere, scans dumps/files/live PIDs, integrates with Volatility and PE-sieve, and encodes threat-intel as reusable rules. |

#### Requirements

- Linux/macOS/Windows. The `yara` CLI (validated here: 4.5.0), or `yara-python` for scripting.

#### Installation

```bash
# Debian/Ubuntu/SIFT
sudo apt install -y yara
# macOS
brew install yara
# Python bindings (any OS)
pip install yara-python
# Source/releases: https://github.com/VirusTotal/yara   ·   docs: https://yara.readthedocs.io
```

#### Configuration

No config. Rules live in `.yar` files; compile a rule set once with `yarac` for speed. Useful flags: `-s` (show matched strings + offsets), `-r` (recurse a directory), `-f` (fast match), `-w` (no warnings), `-d VAR=VALUE` (external variables), `-C` (use a compiled ruleset).

#### Verify the installation

```bash
yara --version
printf 'MZ...PE\0\0' | yara <(echo 'rule t { strings: $=".exe" condition: $ }') /dev/stdin ; true
```

#### First use / quick start

```bash
# Scan a memory dump, showing matched bytes and their offsets
yara -s rules.yar memory.raw
# Recurse a directory of dumps/dropped files
yara -r rules.yar ./evidence/
# Scan a LIVE process by PID (Linux/Windows)
yara rules.yar 4820
# Inside Volatility 3, tie a hit to a process/VAD:
#   vol -f memory.raw windows.vadyarascan --yara-file rules.yar
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| Rule matches everything | Tighten the condition (anchor with `at`, require `N of ($a*)`, add `filesize`/context); generic PE strings over-match. |
| "could not open file" on a PID | Scan as root/Administrator; the process must be readable. |
| Slow on huge dumps | Pre-compile with `yarac`, use `-f`, or scan per-VAD via Volatility instead of the whole image. |
| Wide (UTF-16) strings missed | Add the `wide` modifier (and `ascii` to keep both), as Windows stores most strings wide. |

### 🛠️ Tool 2: PE-sieve / HollowsHunter

| | |
|---|---|
| **What** | PE-sieve (hasherezade) scans **one live process** for implants — injected/replaced PEs, shellcode, hooks, hollowing, doppelgänging, reflective injection — and dumps them. HollowsHunter wraps it to scan **many/all** processes. |
| **Why** | The reference open-source (BSD-2) injection scanners; they both **detect and dump** the implant for analysis, and HollowsHunter can run continuously or as an ETW listener. |

#### Requirements

- Windows; **Administrator** (to open other processes). A live system (not a dump). 64- and 32-bit builds.

#### Installation

```text
Download the latest release (version VER) and run in place — no install:
  PE-sieve:       https://github.com/hasherezade/pe-sieve/releases
  HollowsHunter:  https://github.com/hasherezade/hollows_hunter/releases   (also on Chocolatey)
```

#### Configuration / first use

```text
:: PE-sieve — scan one process by PID, detect shellcode, dump implants to a folder (flags verified
:: from the source; run pe-sieve.exe /help for the full list):
pe-sieve.exe /pid 4820 /shellc /threads /dir .\out\
:: /shellc detect shellcode  /threads scan thread entry points  /imp rebuild imports
:: /data scan non-code regions  /refl use process reflection  /json  /quiet  /minidmp

:: HollowsHunter — sweep processes; select by name/PID, loop, or ETW (64-bit):
hollows_hunter.exe /pname rclone.exe /shellc /dir .\out\
hollows_hunter.exe /loop        :: continuous scanning
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| Access denied on a process | Run as Administrator (some processes need SYSTEM/PPL handling). |
| Too many false positives | Drop `/data`, use `/mignore` to ignore known modules, and triage dumped implants. |
| Need all processes, not one | Use HollowsHunter (PE-sieve is single-process by design). |

### 🛠️ Tool 3: Moneta

| | |
|---|---|
| **What** | A Windows **x64 user-mode memory scanner** (Forrest Orr) that enumerates process memory and flags **IOCs** — private executable memory, image/disk mismatches, hollowing, headerless/unsigned modules, missing PEB entries. |
| **Why** | A fast "what's abnormal in memory right now" triage that reasons about region properties, complementary to signature scanning. |

#### Requirements

- Windows x64; **Administrator** for a full scan. A live system.

#### Installation / use

```text
Download a build from the project and run the x64 executable as Administrator. It scans process
memory and reports IOCs per region/process. The project has no README; consult the repository and
Forrest Orr's write-up for the current options rather than assuming flags:
  Repo:     https://github.com/forrest-orr/moneta
  Write-up: "Masking Malicious Memory Artifacts" (Forrest Orr)
Typical use is to scan a target process (or all processes) and review the flagged regions
(e.g. private +RX, modified image, unsigned module) — then dump and analyse them.
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| Few/no results as a normal user | Run elevated; many regions aren't readable otherwise. |
| Legit JIT/EDR flagged | .NET/Java/browsers and some security tools make private +x memory — correlate before concluding. |
| 32-bit target | Moneta targets x64; use PE-sieve/HollowsHunter for broader coverage. |

---

## Part 3: Hands-on labs

You hunt **WS-ALICE's** stage-2 payload — now resident in a victim process — in a crafted raw slice (`mk_injection_sample.py`) carrying the real artifacts: an x86 shellcode prologue, an in-memory PE, a reflective-loader name, the injection API set, and the C2. `mem_hunt.yar` is a starter rule pack. YARA runs for real; the Windows live-process tools (Part 2) do not run here.

Run on Ubuntu/SIFT. Nothing needs root (the sample is a file).

```bash
sudo apt update && sudo apt install -y yara python3 git
git -C ~/DFIR pull 2>/dev/null || git clone https://github.com/Mr-Phoenix07/DFIR.git ~/DFIR
mkdir -p ~/cases/LAB-025/{evidence,work,notes} && cd ~/cases/LAB-025
export TZ=UTC
yara --version
python3 ~/DFIR/scripts/mk_injection_sample.py evidence/inject.mem
```

```
4.5.0
wrote evidence/inject.mem: 8388608 bytes (2048 pages of 4096), 5 artifact pages
sha256: d83c47ab625c4515769f5f122688ddb46a7de3a49f9de45ba67bcffe744de4e0
```

### Lab 1: A first YARA sweep (10 min)

Point the rule pack at the dump. Each line is a rule that fired on the file:

```bash
yara ~/DFIR/scripts/mem_hunt.yar evidence/inject.mem
```

```
msf_block_api_shellcode evidence/inject.mem
pe_image_in_memory evidence/inject.mem
reflective_loader evidence/inject.mem
injection_api_set evidence/inject.mem
c2_203_0_113_50 evidence/inject.mem
```

Five techniques flagged in one pass: a shellcode stub, a PE image in memory, a reflective loader, the injection API set, and the C2 host. That's the 30-second "is there malcode in here?" answer — now prove each.

### Lab 2: Read the matches by offset (20 min)

`-s` shows *what* matched and *where*, so you can seek to it and tie it to a region/process:

```bash
yara -s ~/DFIR/scripts/mem_hunt.yar evidence/inject.mem
```

```
msf_block_api_shellcode evidence/inject.mem
0x32000:$stub: FC E8 82 00 00 00 60 89 E5 31 C0 64 8B 50 30
pe_image_in_memory evidence/inject.mem
0x78000:$mz: MZ
0x7804e:$dos: This program cannot be run in DOS mode
0x78080:$pe: 50 45 00 00
reflective_loader evidence/inject.mem
0xc8000:$r: ReflectiveLoader
injection_api_set evidence/inject.mem
0xc8011:$a1: VirtualAllocEx
0xc8020:$a2: WriteProcessMemory
0xc8033:$a3: CreateRemoteThread
0xc8046:$a4: NtUnmapViewOfSection
0xc805b:$a5: LoadLibraryA
0xc8068:$a6: GetProcAddress
c2_203_0_113_50 evidence/inject.mem
0xf000e:$ip: 2\x000\x003\x00.\x000\x00.\x001\x001\x003\x00.\x005\x000\x00
```

Each hit has a byte offset. The shellcode stub at `0x32000` is the Metasploit **block-API** prologue (`FC E8 ?? 00 00 00 60 89 E5` …); the PE at `0x78000` is an `MZ`/`PE` image sitting in memory; `ReflectiveLoader` and the six injection APIs cluster at `0xc8000` (the loader resolving what it needs); the C2 is UTF-16LE (note the `\x00` between characters). In a real case you'd now map each offset to its VAD/process with `vol windows.vadyarascan` to learn *which* process is hollowed.

### Lab 3: Confirm at the byte level (15 min)

A rule is a claim; check the bytes. The shellcode prologue and the injected PE header, raw:

```bash
echo '--- shellcode stub (page 50): cld; call; pushad; PEB walk ---'
xxd -s 0x32000 -l 24 evidence/inject.mem
echo '--- injected PE header (page 120): MZ ... PE\0\0 with no file behind it ---'
xxd -s 0x78000 -l 8 evidence/inject.mem
xxd -s 0x78080 -l 8 evidence/inject.mem
```

```
--- shellcode stub (page 50): cld; call; pushad; PEB walk ---
00032000: fce8 8200 0000 6089 e531 c064 8b50 308b  ......`..1.d.P0.
00032010: 520c 8b52 1490 9090                      R..R....
--- injected PE header (page 120): MZ ... PE\0\0 with no file behind it ---
00078000: 4d5a 0000 0000 0000                      MZ......
00078080: 5045 0000 4c01 0000                      PE..L...
```

`fc e8 82 00 00 00 60 89 e5 …` is `cld; call; pushad; mov ebp,esp; …` — the classic position-independent prologue that walks the PEB to resolve APIs. And `MZ` at `0x78000` with `PE\0\0` exactly `0x80` bytes later is a PE header **in memory** — if no file on disk backs this region, that's hollowing or reflective injection, not a normal mapped image.

### Lab 4: Carve the implant for analysis (10 min)

Signatures found it; now extract it the way PE-sieve would dump an implant, for sandboxing or static analysis:

```bash
dd if=evidence/inject.mem bs=4096 skip=120 count=1 of=work/implant.page 2>/dev/null
echo "carved $(wc -c < work/implant.page) bytes for sandboxing / static analysis"
xxd work/implant.page | sed -n '1p;9p'
```

```
carved 4096 bytes for sandboxing / static analysis
00000000: 4d5a 0000 0000 0000 0000 0000 0000 0000  MZ..............
00000080: 5045 0000 4c01 0000 0000 0000 0000 0000  PE..L...........
```

You've pulled the injected PE page straight out of the dump into its own file — `MZ` at `0`, `PE\0\0` at `0x80`. From here it goes to a disassembler or a sandbox. That carve-and-analyse loop — **locate** (structure/signature) → **dump** → **classify** — is the whole of in-memory malcode hunting, whether the locator is YARA, `malfind`, PE-sieve or Moneta.

---

## ✅ Knowledge check

1. `pslist` shows only normal processes, but you're sure the host is compromised. Where is the code, and name two techniques that produce that picture.
2. What single memory property is the strongest generic signal of injected code, and why is it not proof on its own?
3. Classic DLL injection vs reflective DLL injection: which does `dlllist` catch, and why does it miss the other?
4. In process hollowing, the process name and path look legitimate. What comparison exposes it, and which tool makes that comparison?
5. Your YARA rule for `MZ` + "This program cannot be run in DOS mode" + `PE\0\0` fires on dozens of regions. Is that wrong? How do you turn the hits into findings?
6. When would you scan a live process with YARA versus scanning an acquired dump, and what's the cost of the live scan?
7. You have a suspicious `+x` private region at a known offset. Walk the steps from there to a verdict.
8. Why run both a structure-aware scanner (PE-sieve/Moneta) and a signature scanner (YARA) rather than one?

<details>
<summary><b>Answers</b></summary>

1. The code is **inside a legitimate process** (injected), so the process list looks clean. Two techniques: **process hollowing** (a legit process whose in-memory image was replaced) and **reflective DLL / shellcode injection** (code mapped into a host process with no new process and often no module entry). Thread hijacking and classic DLL injection also fit.
2. **Private + executable** memory (a non-image-backed region that is `+x`). Normal code is image-backed; private `+x` is where injected shellcode/manually-mapped PEs live. Not proof because **JIT engines** (.NET, Java, browsers) and some EDR/packers legitimately create private `+x` memory — confirm the owning process and whether code belongs there.
3. `dlllist` catches **classic** injection (the DLL is loaded via `LoadLibrary`, so it appears as a module). It misses **reflective** injection because the payload maps itself without the loader, leaving **no loaded-module entry** (use `ldrmodules`/`malfind` instead).
4. Compare the **in-memory image** of the process to the **file on disk**: hollowing replaces the mapped image, so they differ. **PE-sieve** does this per process (and dumps the difference); Volatility's `ldrmodules`/image checks help too.
5. **Not wrong** — every real PE contains those bytes, so the rule flags *all* PE images, legit included. Turn hits into findings by **context**: which process/VAD is the region in (`vadyarascan`), is it **private/unbacked** (should an image live there?), does the in-memory image **match disk**, and what does the carved PE look like under static analysis.
6. Scan a **dump** by default — repeatable and it doesn't disturb the host. Scan a **live process** when you can't acquire, or need the current state (a region that will be freed). Cost: the live scan **touches the target** (observer effect) and can tip off/alter the malware; document it.
7. Confirm the region is **private and executable** and **unbacked** (not a mapped image); identify the **owning process** and whether that process should have code there; **YARA** the region for known shapes; **dump** it (PE-sieve-style) and run static/sandbox analysis; corroborate with `pslist`/`psscan`, `cmdline`, `netscan` and parent process. Only then conclude.
8. They answer different questions. Structure-aware scanners find the **suspicious region** by its memory properties — even for unknown code — but don't say *what* it is. Signature scanners say **what** a known shape is but miss novel/region-only anomalies. Together: structure locates, signatures classify.

</details>

---

## 📚 Further reading

- YARA documentation (https://yara.readthedocs.io) — writing rules, modules (`pe`, `math`), performance
- PE-sieve (https://github.com/hasherezade/pe-sieve) and HollowsHunter (https://github.com/hasherezade/hollows_hunter) wikis
- Forrest Orr, *Masking Malicious Memory Artifacts* (parts I–III) and Moneta (https://github.com/forrest-orr/moneta)
- MITRE ATT&CK: **T1055** Process Injection (and sub-techniques .001–.015), **T1620** Reflective Code Loading
- Volatility `windows.malfind` and `windows.vadyarascan` docs — structure + signatures together
- *The Art of Memory Forensics*, the code-injection chapters

---

## ⏭️ Tomorrow: Day 26

**Linux & macOS memory acquisition and symbol tables.** Tools: **LiME**, **AVML**, **dwarf2json**.
Phase 3 has been Windows-centric; tomorrow we acquire Linux and macOS RAM (LiME, AVML) and build the **symbol tables** (`dwarf2json`) that Volatility needs for those kernels — the ISF that Day 24's Windows path downloaded for you.

---

<sub>Part of the <a href="../README.md">DFIR Daily</a> series · <a href="../CURRICULUM.md">Full 60-day curriculum</a> · For educational and authorised use only.</sub>
