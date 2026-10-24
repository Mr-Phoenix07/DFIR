# Day 27: Hibernation Files, Pagefile & Crash Dumps

> **Phase 3: Memory Forensics** · **Level:** 🟡→🔴 Intermediate to Advanced · **Time:** ~4 hours (reading + labs) · **Posted:** 2026-10-24
>
> **Tools today:** 🛠️ Hibernation Recon · 🛠️ bstrings · 🛠️ WinDbg

---

## 🎯 Learning objectives

By the end of today you will be able to:

1. Name the three places Windows writes memory to disk — **hiberfil.sys**, **pagefile.sys/swapfile.sys**, and **crash dumps** — and what each contains.
2. Identify each artifact from its header, and say which tool reads it and whether it must be decompressed first.
3. Recover memory from a **hibernation file** with Hibernation Recon (including slack and multiple sessions), and feed the result to Volatility.
4. Carve **pagefile/swap** for strings and IOCs with **bstrings**, in both ASCII and Unicode, using its built-in pattern library.
5. Read a **crash dump** header (stop code, build, CPU) and know how WinDbg and Volatility analyse it — and recognise the anti-forensics that wipe these artifacts.

---

## Part 1: The lesson

A live capture (Days 23–26) isn't the only source of RAM. Windows routinely writes memory **to disk**, and those files survive a reboot — sometimes a wipe. Three of them matter, and each needs different handling.

### 1.1 hiberfil.sys — a snapshot of RAM

When a machine **hibernates** (or does a modern "fast startup" shutdown), Windows compresses the contents of RAM and writes them to `C:\hiberfil.sys`. It is, in effect, a **memory image on disk** — processes, keys, network state as they were at hibernation. Two complications:

- It is **compressed** (modern Windows uses **Xpress-Huffman**), so you can't just run Volatility on the raw file — you **decompress** it first (Hibernation Recon, or Volatility's hibernation layer) into a raw image.
- The file is a fixed size and is **reused**; an old, larger session can leave **slack** — remnants of a *previous* hibernation — after the current one. Good tools recover those older sessions too.

The first bytes tell you the state: `HIBR`/`hibr` (contains a hibernation image), `WAKE`/`RSTR` (resuming), or **zeroed** (resumed-and-cleared, or hibernation disabled). A zeroed hiberfil is empty of evidence.

### 1.2 pagefile.sys / swapfile.sys — paged-out memory

To free RAM, Windows **pages out** memory to `C:\pagefile.sys` (and `swapfile.sys` for UWP apps). Unlike hiberfil, the pagefile is **not a structured image** — it's a bag of 4 KB pages with **no map** of which process or virtual address each came from. So you rarely "analyse" it like a memory image; instead you **carve** it: strings, IOCs (URLs, IPs, SIDs), command fragments, cached credentials, chat/keystroke remnants. A page that was swapped out hours ago can hold evidence that's **gone from a live capture**. Because Windows keeps most strings as **UTF-16LE**, you scan both encodings — the job for **bstrings**.

### 1.3 Crash dumps — state at a bug check

When Windows bug-checks (BSOD) it writes a **crash dump**. The flavours, by how much they contain: **complete/full** (all physical memory), **kernel** (kernel memory only — the default on many systems), **active** (active memory, Win10+), **automatic** (kernel, with a managed pagefile), and a tiny **minidump** (`%SystemRoot%\Minidump\*.dmp`, ~64–256 KB). A kernel/complete dump is a real (partial) memory image a framework can analyse; a minidump is just enough for a debugger to blame a driver.

The header (`_DUMP_HEADER64` on x64) starts `PAGE` + `DU64` (or `DUMP` on x86) and records the **bug-check code** (the stop code, e.g. `0x7E SYSTEM_THREAD_EXCEPTION_NOT_HANDLED`) and its parameters, the NT build, the CPU type and count, and the physical-memory run map. **WinDbg** opens it (`!analyze -v`); **Volatility**'s crash layer reads a kernel/complete dump directly (Day 24).

### 1.4 Getting memory out, and anti-forensics

The workflow per artifact:

- **hiberfil.sys** → decompress with **Hibernation Recon** (or Volatility's hibernation layer) → raw image → Volatility `windows.*`.
- **pagefile.sys/swapfile.sys** → **carve** with bstrings/strings; optionally combine with a memory image so Volatility can follow pages that were swapped (`--pagefile`).
- **crash dump** → **WinDbg** for the stop code and the faulting driver; **Volatility** for processes/DLLs/network in a kernel/complete dump.

Anti-forensics cuts all three off: **`ClearPageFileAtShutdown`** zeroes the pagefile on shutdown; hibernation is often **disabled** (`powercfg /h off` deletes `hiberfil.sys`); and crash dumps can be set to **none**. Absence isn't innocence — note *which* artifact is missing or zeroed and why.

Today's labs **run bstrings for real** to carve a pagefile slice, and identify a crash dump and a hibernation file from their headers. **Hibernation Recon** and **WinDbg** are Windows-only (documented, not run here); the crash dump and hiberfil are header stand-ins (no real compressed body to decompress).

---

## Part 2: Tools

**bstrings** runs here (.NET 10 via `dotnet`). **Hibernation Recon** and **WinDbg** are Windows-only and need a real hiberfil/dump, so they're documented. `VER` is the version you fetch.

### 🛠️ Tool 1: Hibernation Recon

| | |
|---|---|
| **What** | Arsenal Recon's Windows tool to decompress and reconstruct Windows hibernation files into raw memory. |
| **Why** | Handles every modern Windows compression format and, crucially, recovers **active** memory *and* **slack** from older hibernation sessions that other tools miss. |

#### Requirements

- Windows; a `hiberfil.sys` (or carved hibernation data). A free edition exists; some features are licensed.

#### Installation

```text
Download Hibernation Recon (version VER) from https://arsenalrecon.com/products (Windows installer/zip).
No Linux build; run on a Windows analysis host. Confirm steps against the vendor documentation.
```

#### Configuration / first use

```text
1. Launch Hibernation Recon; select the input hiberfil.sys.
2. Choose output folder; enable recovery of active memory and slack/older sessions.
3. Run; it writes raw .bin memory image(s) (one per recovered session) plus reports.
4. Feed the raw output to Volatility:  vol -f active_memory.bin windows.pstree
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| "Not a hibernation file" / empty | Header is zeroed — hibernation was cleared/disabled; no image to recover. |
| Only current session recovered | Enable slack/old-session recovery; a larger prior hibernation can hide in the file's tail. |
| Volatility can't parse the output | Point it at the **decompressed raw** image (not `hiberfil.sys` itself); match symbols as usual. |

### 🛠️ Tool 2: bstrings

| | |
|---|---|
| **What** | Eric Zimmerman's "better strings": finds ASCII **and** UTF-16LE strings, with a library of built-in regex patterns (IPs, GUIDs, SIDs, URLs, emails, …) and offsets. |
| **Why** | Pagefile/swap and slack are unstructured — carving strings and IOCs is the whole game, and bstrings does both encodings, regex and offsets in one pass. |

#### Requirements

- The .NET 10 runtime (`dotnet bstrings.dll` on any OS), or the .NET Framework 4.7.2 build on Windows.

#### Installation

```bash
# Prebuilt (version VER): https://ericzimmerman.github.io  (bstrings.zip, .NET 10) — or Get-ZimmermanTools
# From source (any OS with the .NET SDK):
git clone https://github.com/EricZimmerman/bstrings
dotnet build bstrings/bstrings/bstrings.csproj -c Release -f net10.0
# run as:  dotnet .../bstrings.dll [options]
```

#### Configuration / first use

```bash
dotnet bstrings.dll -p                                   # list the built-in regex patterns
dotnet bstrings.dll -f pagefile.sys --lr ipv4 --off      # built-in IPv4 pattern, with offsets
dotnet bstrings.dll -f pagefile.sys --lr 'http[s]?://[^ ]+' --ro    # custom regex, return the match
dotnet bstrings.dll -f pagefile.sys -a false -u --ls Password       # Unicode-only, literal string
dotnet bstrings.dll -f pagefile.sys --lr sid -o hits.txt -s         # write hits to a file, quiet
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| Timing/stats clutter the output | Write hits with `-o FILE -s` (really quiet) and read the file; the file holds just the matches. |
| Missing obvious Windows strings | Add the Unicode pass (`-u`); most Windows strings are UTF-16LE and an ASCII-only scan skips them. |
| Want just the matched substring | Use `--ro` (approx offset, shown with `~`); without it, bstrings returns the whole string the pattern was found in. |

### 🛠️ Tool 3: WinDbg

| | |
|---|---|
| **What** | Microsoft's debugger — opens crash dumps (and live kernels) to analyse the bug check and system state. |
| **Why** | The authoritative reader of Windows crash dumps: it decodes the stop code, blames the faulting driver, and walks threads/stacks. |

#### Requirements

- Windows. Install **WinDbg** (modern "WinDbg" from the Store / the Windows SDK's Debugging Tools). Symbols from Microsoft's public symbol server.

#### Installation

```text
Install WinDbg (version VER) from the Microsoft Store, or "Debugging Tools for Windows" in the
Windows SDK: https://learn.microsoft.com/windows-hardware/drivers/debugger/
Set the symbol path to the public server (srv*https://msdl.microsoft.com/download/symbols).
```

#### Configuration / first use

```text
1. File -> Open dump file -> crashdump.dmp (or Minidump\*.dmp).
2. Set symbols:  .sympath srv*C:\symbols*https://msdl.microsoft.com/download/symbols ; .reload
3. !analyze -v        -> stop code, faulting module, and a probable-cause summary
4. lm / !process 0 0 / !thread for modules, processes and stacks (full/kernel dumps).
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| "Wrong symbols" / junk stacks | Fix `.sympath` to the public server and `.reload`; a minidump needs matching symbols to be useful. |
| Minidump shows little | By design — it's tiny (driver blame only); use a kernel/complete dump for real memory analysis. |
| Prefer processes/network | Open a kernel/complete dump in **Volatility** (crash layer, Day 24); WinDbg is best for the bug check itself. |

---

## Part 3: Hands-on labs

You triage the on-disk memory artifacts from the WS-ALICE host. `mk_diskmem_samples.py` writes a pagefile slice, a Windows kernel crash-dump header and a hibernation-file header; `dump_triage.py` identifies each; and **bstrings** (built here with `dotnet`) carves the pagefile for real. The crash dump and hiberfil are header stand-ins (no real compressed body), so Hibernation Recon/WinDbg aren't run — Part 2 has their steps.

Run on Ubuntu/SIFT with the .NET SDK. The first run builds bstrings (a minute); nothing needs root.

```bash
sudo apt update && sudo apt install -y git python3 dotnet-sdk-10.0 binutils
git -C ~/DFIR pull 2>/dev/null || git clone https://github.com/Mr-Phoenix07/DFIR.git ~/DFIR
mkdir -p ~/cases/LAB-027/{evidence,work,notes} ~/tools && cd ~/cases/LAB-027
export TZ=UTC
[ -d ~/tools/bstrings ] || git clone -q https://github.com/EricZimmerman/bstrings ~/tools/bstrings
dotnet build ~/tools/bstrings/bstrings/bstrings.csproj -c Release -f net10.0 -v q >/dev/null 2>&1
BS=~/tools/bstrings/bstrings/bin/Release/net10.0/bstrings.dll
bstr() { dotnet "$BS" "$@"; }
python3 ~/DFIR/scripts/mk_diskmem_samples.py evidence
echo "bstrings $(bstr --version 2>/dev/null | grep -oE '[0-9]{4}\.[0-9]+\.[0-9]+' | head -1)"
```

```
wrote evidence/pagefile.sys: 16342 bytes
wrote evidence/crashdump.dmp: 12288 bytes
wrote evidence/hiberfil.sys: 4096 bytes
bstrings 2026.10.0
```

### Lab 1: Identify each artifact from its header (10 min)

Before any heavy tool, say what you're holding:

```bash
python3 ~/DFIR/scripts/dump_triage.py evidence/crashdump.dmp evidence/hiberfil.sys evidence/pagefile.sys
```

```
evidence/crashdump.dmp
  type:    Windows kernel crash dump (x64)  -> WinDbg, or Volatility crash layer
  version: NT 15.26100   machine: x64 (AMD64)   processors: 8
  bugcheck: 0x7e SYSTEM_THREAD_EXCEPTION_NOT_HANDLED   param1: 0xffffffffc0000005

evidence/hiberfil.sys
  type:    Windows hibernation file (signature 'HIBR')  -> Hibernation Recon / Volatility (decompress Xpress-Huffman)
  state:   contains a hibernated RAM image (compressed); decompress before analysis

evidence/pagefile.sys
  type:    no known header -> raw/padded physical image, or a pagefile/swap slice
           (unstructured paged-out memory; carve with strings / bstrings)
```

Three different artifacts, three different next steps. The **crash dump** reads cleanly — an x64 bug check `0x7E` (`SYSTEM_THREAD_EXCEPTION_NOT_HANDLED`) with an access-violation parameter, NT build 26100, 8 CPUs — enough to start a WinDbg triage. The **hiberfil** says `HIBR`: a compressed RAM image to decompress with Hibernation Recon before analysis. The **pagefile** has no header — unstructured paged-out memory, which you carve.

### Lab 2: Carve the pagefile with bstrings (20 min)

The pagefile is a bag of pages; the value is the IOCs in them. bstrings has a built-in pattern library and takes custom regexes, in one pass over both encodings:

```bash
echo "bstrings built-in patterns: $(bstr -p 2>/dev/null | grep -cE '^[A-Za-z]')"
bstr -f evidence/pagefile.sys --lr ipv4 --ro --off -o work/ips.txt -s > /dev/null 2>&1
bstr -f evidence/pagefile.sys --lr 'http[s]?://[^ ]+' --ro -o work/urls.txt -s > /dev/null 2>&1
cat work/ips.txt work/urls.txt
```

```
bstrings built-in patterns: 29
203.0.113.50	~0x100 (A)
10.20.30.40	~0x480 (A)
http://203.0.113.50/gate.php
```

From memory that was swapped to disk: the C2 IP (twice — in the request and the connection fragment) and the full C2 URL, each with its offset. This is evidence that may be **gone from a live capture** (the pages were paged out), recovered straight off the disk.

### Lab 3: The Unicode strings GNU `strings` misses (10 min)

Windows keeps most strings as UTF-16LE. An ASCII-only scan — the default `strings` — walks straight past them:

```bash
echo '--- GNU strings (ASCII only) looking for the credential: ---'
strings -n 8 evidence/pagefile.sys | grep -c 'Autumn2026'
echo '--- bstrings Unicode pass finds it, with offset and encoding (U): ---'
bstr -f evidence/pagefile.sys -a false -u --ls Password --off -o work/cred.txt -s > /dev/null 2>&1
cat work/cred.txt
```

```
--- GNU strings (ASCII only) looking for the credential: ---
0
--- bstrings Unicode pass finds it, with offset and encoding (U): ---
DefaultPassword=Autumn2026!	0xC00 (U)
```

GNU `strings` finds the credential **zero** times; bstrings' Unicode pass pulls `DefaultPassword=Autumn2026!` out at offset `0xC00`, marked `(U)` for UTF-16. A cleartext password, paged out of `lsass` or a logon prompt and left on disk — exactly the kind of thing a pagefile coughs up, and exactly what you'd miss with an ASCII-only tool.

---

## ✅ Knowledge check

1. Name the three on-disk sources of memory and, in one phrase each, what they contain.
2. Why can't you run Volatility directly on `hiberfil.sys`, and what do you do first?
3. A hiberfil's first bytes are all zero. What does that most likely mean for your investigation?
4. Why do you *carve* the pagefile rather than analyse it like a memory image?
5. Evidence is in a live capture **and** in the pagefile — what can the pagefile add that the capture can't?
6. A minidump and a complete dump are both `.dmp`. Which do you open in WinDbg vs Volatility, and why?
7. Your ASCII `strings` run on a pagefile finds little of interest, yet you expect credentials. What did you forget?
8. Three anti-forensic settings can empty these artifacts. Name them, and say how you'd report the gap.

<details>
<summary><b>Answers</b></summary>

1. **hiberfil.sys** — a compressed snapshot of RAM at hibernation; **pagefile.sys/swapfile.sys** — paged-out memory pages (unstructured); **crash dumps** — memory/state captured at a bug check (from tiny minidump to complete).
2. hiberfil is **compressed** (Xpress-Huffman) and not a flat image. **Decompress** it first — Hibernation Recon or Volatility's hibernation layer — into a raw image, then analyse that.
3. The hibernation image was **cleared/disabled** (resumed-and-zeroed, or `powercfg /h off`) — there's **no memory to recover** from it. Note the absence; it's not evidence of what ran.
4. The pagefile has **no map** of which process/virtual address each page belonged to — it's just pages. Without that structure a framework can't reconstruct processes, so you **carve** strings/IOCs instead (and, optionally, pair it with a memory image via `--pagefile`).
5. Pages **swapped out earlier** — strings, IOCs, credentials, command fragments from state that has since changed or been freed in RAM, so the live capture no longer holds it.
6. **Minidump → WinDbg** (tiny; driver/stop-code blame only). **Kernel/complete dump → Volatility** (a real partial memory image: processes, DLLs, network), and WinDbg for the bug check. A minidump in Volatility gives little.
7. The **Unicode (UTF-16LE) pass** — Windows stores most strings wide, so an ASCII-only `strings` skips them. Use bstrings with `-u` (or `strings -e l`).
8. **`ClearPageFileAtShutdown`** (zeroes the pagefile), **hibernation disabled/deleted** (`powercfg /h off`), and **crash dumps set to none**. Report *which* artifact is missing or zeroed, the setting that explains it, and treat the period as a **gap** — absence of the artifact, not absence of activity.

</details>

---

## 📚 Further reading

- Arsenal Recon, *Hibernation Recon* (https://arsenalrecon.com) and its documentation on slack/older sessions
- Eric Zimmerman, *bstrings* (https://github.com/EricZimmerman/bstrings) and the Get-ZimmermanTools suite
- Microsoft Learn: *Analyze crash dump files with WinDbg*, and the bug-check (stop code) reference
- Volatility 3 `windows.crashinfo`, the crash and hibernation layers, and the `--pagefile` option
- Microsoft Learn: *Varieties of kernel-mode dump* (complete/kernel/active/automatic/mini)
- *The Art of Memory Forensics* — the hibernation, pagefile and crash-dump chapters

---

## ⏭️ Tomorrow: Day 28

**Network forensics fundamentals & packet capture.** Tools: **tcpdump**, **Wireshark**, **NetworkMiner**.
Phase 3 ends with memory; Phase 4 opens on the wire. Tomorrow we capture and read packets — the other half of the WS-ALICE story, where the C2 traffic you kept finding in memory actually flowed.

---

<sub>Part of the <a href="../README.md">DFIR Daily</a> series · <a href="../CURRICULUM.md">Full 60-day curriculum</a> · For educational and authorised use only.</sub>
