# Day 24: Memory Analysis Essentials — Processes, DLLs, Handles, Network

> **Phase 3: Memory Forensics** · **Level:** 🔴 Advanced · **Time:** ~4 hours (reading + labs) · **Posted:** 2026-10-21
>
> **Tools today:** 🛠️ Volatility 3 · 🛠️ Volatility Workbench · 🛠️ MemProcFS

---

## 🎯 Learning objectives

By the end of today you will be able to:

1. Explain the two things a memory framework needs to turn raw bytes into a process list: a **translation layer** and a **symbol table**.
2. Find processes two ways — **list-walking** (`pslist`) and **scanning** (`psscan`) — and say why the difference catches hidden processes.
3. Answer the core questions of a memory case with the right plugin: processes, command lines, DLLs/modules, handles, network, services.
4. Use **Volatility 3** on the command line, **Volatility Workbench** as a GUI front-end, and **MemProcFS** to mount an image as a filesystem.
5. Recognise what breaks an analysis — wrong symbols, a smeared image, DKOM unlinking — and corroborate rather than trust one plugin.

---

## Part 1: The lesson

Yesterday you captured RAM and skimmed its strings. Strings found indicators, but they couldn't tell you **which process** owned a connection, **what DLLs** it had loaded, or **which parent** spawned it. Those answers live in the operating system's own data structures, scattered across physical memory. Today you give the bytes structure.

### 1.1 From bytes to a process list: layers and symbols

A raw dump is physical memory — but the OS and every process think in **virtual** addresses. To follow a kernel pointer you must translate virtual → physical, and that needs the **Directory Table Base** (the `DTB`/`CR3` value, the root of the page tables). Volatility builds a **translation layer** that does this for the whole image. That is the first half of yesterday's `windows.info` error — *"a translation layer requirement was not fulfilled"*: a flat triage sample has no identifiable kernel, so no layer can be built.

The second half is the **symbol table**. The meaning of the bytes — where in an `_EPROCESS` the PID sits, where the name is, where the "next process" pointer points — depends on the **exact OS build**. Volatility ships none of this for Windows; it reads the kernel's debug **banner/GUID** from the image and fetches the matching **ISF** (Intermediate Symbol Format, a JSON of types and offsets) from its symbol server, caching it. That is the other half of the error — *"a symbol table requirement was not fulfilled"*. No two things, no analysis. (Day 26 builds ISF for Linux by hand with `dwarf2json`.)

### 1.2 Finding processes two ways

Once the layer and symbols exist, there are two ways to enumerate processes, and the gap between them is where rootkits hide:

- **List-walking (`windows.pslist`)** follows the kernel's own doubly-linked list of active processes (`ActiveProcessLinks`), starting from a known anchor. Fast and accurate — *for processes the kernel still lists*.
- **Scanning (`windows.psscan`)** ignores the list and sweeps **all** of memory for anything that looks like an `_EPROCESS` (by pool tag and structure). It finds processes that have **exited** (not yet overwritten) and ones a **DKOM** rootkit **unlinked** from the list to hide them.

A process in `psscan` but **not** in `pslist` is a red flag: it was hidden or has terminated. `windows.pstree` renders the parent/child hierarchy — the fastest way to spot wrong parentage (an Office app spawning `powershell.exe`, or `rclone.exe` whose parent is a one-off `cmd.exe`).

### 1.3 The core questions and their plugins

A memory investigation is a handful of questions. For each, a plugin and what it proves:

| Question | Volatility 3 plugin | What it gives you |
|---|---|---|
| What ran? | `windows.pslist` / `windows.psscan` / `windows.pstree` | PIDs, parents, start/exit times; hidden/terminated via the scan |
| With what command line? | `windows.cmdline` | full arguments — the download cradle, the rclone flags, the C2 URL |
| What code was loaded? | `windows.dlllist` / `windows.ldrmodules` | loaded DLLs and their paths; `ldrmodules` flags unlinked (injected) modules |
| What did it hold open? | `windows.handles` | open files, registry keys, mutexes (malware's single-instance marker), named pipes |
| What was on the wire? | `windows.netscan` / `windows.netstat` | sockets and connections — local/remote IP:port, owning PID, state |
| What services exist? | `windows.svcscan` | service name, type, state, binary path (Day 22's persistence, from RAM) |
| Any injected code? | `windows.malfind` | private, executable, unbacked regions — shellcode/hollowing (Day 25) |

The same questions have Linux (`linux.pslist`, `linux.lsof`, `linux.bash`…) and macOS plugins — 59 and 23 of them — because the *questions* are OS-agnostic even though the structures differ.

### 1.4 What breaks an analysis

- **Wrong or missing symbols.** A profile for the wrong build gives empty results or nonsense offsets. If a plugin returns nothing, suspect the symbols before the evidence.
- **A smeared image.** Acquisition isn't atomic (Day 23), so a pointer read late may not match a structure read early; a list walk can dead-end. Corroborate `pslist` with `psscan`.
- **Anti-forensics.** DKOM **unlinks** a process from `ActiveProcessLinks` to hide it from `pslist` — `psscan` still finds it. Code injection hides from `dlllist` (no loaded-module entry) — `ldrmodules`/`malfind` catch it. Never conclude from one plugin.
- **Time.** Timestamps come from the image in **UTC**; note the host's clock skew from your acquisition record.

Today's labs run **Volatility 3 for real** — install, the plugin catalogue, the symbol/layer machinery, and the exact error a non-image produces — but the process/DLL/handle/network plugins need a **real Windows capture**, which can't be made or downloaded on this Linux box. Part 2 shows those commands and representative output; run them against your own capture or a public sample.

---

## Part 2: Tools

**Volatility 3** is cross-platform and we install and run it for real below. **Volatility Workbench** is a Windows-only GUI, and **MemProcFS** needs a real image (and a release binary we can't fetch here), so both are documented, not run. `VER` stands in for the version you download.

### 🛠️ Tool 1: Volatility 3

| | |
|---|---|
| **What** | The open-source memory-analysis framework (Volatility Foundation), a ground-up Python 3 rewrite of Volatility 2. |
| **Why** | The reference tool: 90+ Windows plugins plus Linux and macOS, automatic symbol handling, scriptable, the input to most other tooling. |

#### Requirements

- Python 3.8+ (any OS). Internet access on first analysis, to fetch Windows symbols.
- A **raw** (or crash/LiME/EWF) memory image to analyse.

#### Installation

```bash
# PyPI, in a virtual environment (validated here: 2.28.2)
python3 -m venv ~/tools/vol-venv
~/tools/vol-venv/bin/pip install volatility3==VER
~/tools/vol-venv/bin/vol --help | head -1
# From source (latest):
#   git clone https://github.com/volatilityfoundation/volatility3
#   pip install -e ./volatility3
# Releases / docs: https://github.com/volatilityfoundation/volatility3  ·  https://volatility3.readthedocs.io
```

#### Configuration

None required. Symbols are fetched and cached automatically on first use; to work **offline**, pre-download the symbol packs (see the docs) and point `-s`/`--symbol-dirs` at them. `-r pretty|csv|json` changes the output renderer; `-o DIR` sets a dump directory for plugins that extract files.

#### Verify the installation

```bash
vol --help | head -1            # prints: Volatility 3 Framework VER
vol -h | grep -c windows.       # the Windows plugins are present
```

#### First use / quick start

```bash
# Confirm the image and its build first:
vol -f memory.raw windows.info
# The core questions:
vol -f memory.raw windows.pstree           # process hierarchy (spot wrong parentage)
vol -f memory.raw windows.cmdline          # full command lines
vol -f memory.raw windows.netscan          # sockets and connections (PID, remote IP)
vol -f memory.raw windows.dlllist --pid 4820
vol -f memory.raw windows.handles --pid 4820
vol -f memory.raw windows.malfind -o ./dump   # injected regions (Day 25)
```

Representative `windows.pstree` output **(illustrative — from a real capture, not produced on this Linux lab box)**:

```text
PID    PPID   ImageFileName    CreateTime (UTC)
624    428    explorer.exe     2026-09-29 01:01:11
* 4120 624    cmd.exe          2026-09-29 01:21:03
** 4820 4120  rclone.exe       2026-09-29 01:21:30     <- data-exfil child of a one-off cmd.exe
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| "Unsatisfied requirement ... layer_name / symbol_table_name" | Not a valid/clean image, or symbols couldn't be fetched — verify the file and your network, or supply symbols with `-s`. |
| A plugin returns nothing | Suspect wrong symbols/build before the evidence; confirm with `windows.info`, try `psscan` vs `pslist`. |
| First run hangs on symbols | It's downloading the ISF pack; pre-cache for offline/air-gapped work. |
| Huge image is slow | Use `--parallelism threads`, and target a `--pid` instead of dumping everything. |

### 🛠️ Tool 2: Volatility Workbench

| | |
|---|---|
| **What** | A free **Windows GUI** front-end for Volatility (by PassMark Software). |
| **Why** | Point-and-click plugin selection, saved output, and no command-line memorising — good for triage and for analysts new to Volatility. |

#### Requirements

- Windows; the bundled Volatility (check whether the build wraps Volatility 2 or 3 for the plugins you need). A raw/crash image.

#### Installation

```text
Download Volatility Workbench (version VER) from https://www.osforensics.com/tools/volatility-workbench.html
and unzip; run VolatilityWorkbench.exe. No install step. Windows only.
```

#### Configuration

Select the **image file**, pick the **platform/profile**, then choose a **command** (plugin) from the drop-down; output is shown in the window and can be saved to CSV/text.

#### Verify the installation / first use

```text
1. Launch VolatilityWorkbench.exe.
2. "Select image" -> your .raw/.dmp; set the platform.
3. Choose a command (e.g. Process List / pstree), click "Go"; save the output.
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| Plugin missing vs CLI | The GUI exposes the plugins of its bundled Volatility version; use the Volatility 3 CLI for the newest plugins. |
| Slow / unresponsive on a big image | Expected for a GUI; prefer the CLI for large captures and scripting. |

### 🛠️ Tool 3: MemProcFS

| | |
|---|---|
| **What** | Mounts a memory image (or live memory) as a **browsable filesystem** — processes, handles, registry and more appear as files and folders. |
| **Why** | Explore memory with `ls`/`cat` and any file tool, and re-run analysis by re-reading files; great for pivoting and for scripting without a plugin API. |

#### Requirements

- Windows (with the Dokany driver) **or** Linux (FUSE). The MemProcFS binaries and the LeechCore library. A raw/crash/LiME image (or a live device).

#### Installation

```text
Download MemProcFS (version VER) for your OS from https://github.com/ufrisk/MemProcFS/releases
(Windows needs the Dokany file-system driver; Linux uses FUSE). Unzip and run in place.
Docs/wiki: https://github.com/ufrisk/MemProcFS/wiki
```

#### Configuration / first use

```text
# Mount a raw image as a filesystem, then browse it:
#   Windows:  memprocfs.exe -device memory.raw -mount M:
#   Linux:    ./memprocfs -device memory.raw -mount /mnt/mem
# Then, for example:
#   ls /mnt/mem/name/              # one folder per process (name-pid)
#   cat /mnt/mem/sys/net/netstat.txt
#   ls /mnt/mem/name/rclone.exe-4820/handles/
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| Won't mount on Windows | Install the **Dokany** driver that matches the MemProcFS build. |
| Won't mount on Linux | Ensure **FUSE** is installed and you have permission (`fusermount`). |
| Empty/odd process folders | Wrong or missing symbols — MemProcFS uses the same symbol mechanism; check connectivity/offline symbols. |

---

## Part 3: Hands-on labs

These install and run **Volatility 3 for real**, and show *why* it needs a real capture. The process/DLL/handle/network plugins (Part 2) require a genuine Windows image, which can't be acquired or downloaded on this Linux box — so here you exercise the framework itself: identify an image's format, read the plugin catalogue and the symbol/layer machinery, and watch exactly what happens when you point it at bytes with no OS structure (yesterday's triage sample). `mem_image_check.py` is the 30-second "what am I holding?" pre-flight.

Run on Ubuntu/SIFT. Volatility 3 is pure Python; nothing needs root.

```bash
sudo apt update && sudo apt install -y git python3 python3-venv
git -C ~/DFIR pull 2>/dev/null || git clone https://github.com/Mr-Phoenix07/DFIR.git ~/DFIR
mkdir -p ~/cases/LAB-024/{evidence,work,notes} ~/tools && cd ~/cases/LAB-024
export TZ=UTC
python3 ~/DFIR/scripts/mk_mem_sample.py evidence/ws-alice.mem
[ -d ~/tools/vol-venv ] || python3 -m venv ~/tools/vol-venv
~/tools/vol-venv/bin/pip install -q volatility3==2.28.2 2> /dev/null
vol() { ~/tools/vol-venv/bin/vol "$@"; }
vol --help 2>/dev/null | head -n 1
```

```
wrote evidence/ws-alice.mem: 16777216 bytes (4096 pages of 4096), 8 artifact pages
sha256: 3421712540af37d5b51ec1648020c9fa46bdb4fc595e571b295e9a0a941d5542
Volatility 3 Framework 2.28.2
```

### Lab 1: Identify the image before you analyse it (10 min)

Volatility chooses a layer and symbols from what the file *is*, so name it first. Run the pre-flight on yesterday's sample and on two stub images carrying real format magic (the kinds you'll meet in Days 26–27):

```bash
printf 'EMiL\x01\x00\x00\x00' > evidence/linux.lime && truncate -s 1M evidence/linux.lime
printf 'PAGEDU64' > evidence/crash.dmp && truncate -s 1M evidence/crash.dmp
python3 ~/DFIR/scripts/mem_image_check.py evidence/ws-alice.mem evidence/linux.lime evidence/crash.dmp
```

```
evidence/ws-alice.mem
  size:   16777216 bytes (16 MiB)
  pages:  4096 x 4096
  format: no known container magic -> raw / padded physical memory
  banner: no Linux kernel banner in first/last 64 KiB (Windows image, or banner elsewhere - let Volatility's banners plugin scan it all)

evidence/linux.lime
  size:   1048576 bytes (1 MiB)
  pages:  256 x 4096
  format: LiME format (Linux Memory Extractor, Day 26) - Volatility: lime layer
  banner: no Linux kernel banner in first/last 64 KiB (Windows image, or banner elsewhere - let Volatility's banners plugin scan it all)

evidence/crash.dmp
  size:   1048576 bytes (1 MiB)
  pages:  256 x 4096
  format: Windows crash dump, 64-bit (Day 27) - Volatility: crash layer
  banner: no Linux kernel banner in first/last 64 KiB (Windows image, or banner elsewhere - let Volatility's banners plugin scan it all)
```

The WS-ALICE sample is **raw/padded** with no container magic and no Linux banner — a plain physical dump, which is what WinPmem and the vendor tools wrote. The two stubs are recognised by their magic as **LiME** (Linux, Day 26) and a **Windows crash dump** (Day 27), each of which Volatility reads through a different layer. Knowing this up front stops you from feeding a crash dump to a raw layer and getting nonsense.

### Lab 2: The plugin catalogue (10 min)

Volatility's reach is its plugins. Count them by OS, then pick out the ones that answer this week's questions:

```bash
echo '--- analysis plugins by OS ---'
vol -h 2>/dev/null | grep -oE '^[[:space:]]+(windows|linux|mac)\.[A-Za-z0-9_]+' | sed -E 's/^ +//; s/\..*//' | sort | uniq -c
echo '--- the Windows plugins this week uses ---'
vol -h 2>/dev/null | grep -oE 'windows\.(pslist|pstree|dlllist|handles|cmdline|netscan|netstat|malfind|svcscan)\b' | sort -u
```

```
--- analysis plugins by OS ---
     59 linux
     23 mac
     91 windows
--- the Windows plugins this week uses ---
windows.cmdline
windows.dlllist
windows.handles
windows.malfind
windows.netscan
windows.netstat
windows.pslist
windows.pstree
windows.svcscan
```

Ninety-plus Windows plugins, and dozens each for Linux and macOS — the *questions* (processes, DLLs, handles, network) are the same across platforms; only the structures differ. The nine listed are the backbone of a Windows memory case.

### Lab 3: Layers and symbols — the machinery (10 min)

The two things from the lesson, made concrete. The symbol cache is empty until Volatility fetches a pack for a specific image; the **automagic** is what builds the address layer and locates the symbols:

```bash
echo '--- symbol tables cached locally (empty until Volatility fetches them per image) ---'
vol -q isfinfo 2>/dev/null
echo '--- the automagic that builds the address layer and locates symbols ---'
vol -q frameworkinfo 2>/dev/null | sed -n '/^Automagic/,/^Requirement/p' | grep -vE '^Requirement'
```

```
--- symbol tables cached locally (empty until Volatility fetches them per image) ---
Volatility 3 Framework 2.28.2

URI	Valid	Number of base_types	Number of types	Number of symbols	Number of enums	Identifying information

--- the automagic that builds the address layer and locates symbols ---
Automagic
* ConstructionMagic
* LayerStacker
* SymbolCacheMagic
* KernelModule
* WinSwapLayers
* SymbolFinder
* LinuxSymbolFinder
* MacSymbolFinder
* KernelPDBScanner
```

`isfinfo` lists the Intermediate Symbol Format tables cached locally — **none yet**, because Volatility downloads the pack matching each image's kernel on first use. The automagic list is the pipeline that runs before any plugin: stack the layers, find the kernel, match a symbol table (`KernelPDBScanner`, `SymbolFinder`). When this pipeline can't complete, you get the error in the next lab.

### Lab 4: Why a real capture (and symbols) is non-negotiable (10 min)

Point Volatility at the flat triage sample — valid bytes, but no OS structure — and read the failure precisely:

```bash
vol -q -f evidence/ws-alice.mem windows.info 2>/dev/null
```

```
Volatility 3 Framework 2.28.2

Unsatisfied requirement plugins.Info.kernel.layer_name: 
Unsatisfied requirement plugins.Info.kernel.symbol_table_name: 

A translation layer requirement was not fulfilled.  Please verify that:
	A file was provided to create this layer (by -f, --single-location or by config)
	The file exists and is readable
	The file is a valid memory image and was acquired cleanly

A symbol table requirement was not fulfilled.  Please verify that:
	The associated translation layer requirement was fulfilled
	You have the correct symbol file for the requirement
	The symbol file is under the correct directory or zip file
	The symbol file is named appropriately or contains the correct banner
```

Two unmet requirements: **no translation layer** (the file isn't a clean image of a kernel it can identify) and **no symbol table** (nothing to fetch symbols *for*). This is the lesson's whole point in one message — strings (Day 23) need neither, but *structure-aware* analysis needs **both**. Give Volatility a real WinPmem capture of WS-ALICE and the same `windows.info` prints the build and DTB, after which `pstree`, `cmdline`, `netscan` and the rest (Part 2) answer the case. That capture, and its analysis, is the step this Linux lab can't perform — but the commands above are exactly the ones you'd run.

---

## ✅ Knowledge check

1. Volatility needs two things before any plugin can run. Name them, and say what each one does.
2. `windows.pslist` shows 42 processes; `windows.psscan` shows 44. What are the two extra, most likely, and which should you trust?
3. A connection to `203.0.113.50` is in the dump. Which plugin ties it to a process, and what does it give you beyond the IP?
4. `windows.dlllist` shows nothing unusual for a process you suspect is injected. Why might that be, and which plugin catches it instead?
5. You run `windows.pslist` and get an empty table on an image you know is good. What's the most likely cause, and how do you confirm it?
6. Why are there Linux and macOS plugins at all — isn't memory analysis Windows work? What's common and what differs?
7. You have only a Linux analysis box and a raw Windows capture. Can you still run the full process/DLL/network analysis? What do you (and don't you) need Windows for?
8. What does MemProcFS give you that the Volatility CLI doesn't, and what does it still depend on?

<details>
<summary><b>Answers</b></summary>

1. A **translation layer** (virtual↔physical address translation, built from the DTB/page tables, so kernel pointers can be followed) and a **symbol table** (an ISF for the exact OS build, giving the offsets/meaning of each structure field). Without the layer there are no usable pointers; without symbols the bytes have no meaning.
2. The two extra are most likely a **terminated** process (its `_EPROCESS` not yet overwritten) and/or one a **DKOM** rootkit **unlinked** from the active-process list to hide it. `psscan` (signature scan) sees both; `pslist` (list walk) misses the hidden one — so a scan-only process is the suspicious one. Trust neither alone; the *difference* is the finding.
3. `windows.netscan` (or `netstat`). Beyond the remote IP it gives the **local IP:port, the protocol, the connection state, and the owning PID/process** — which turns "someone talked to the C2" into "`rclone.exe`, PID 4820, had an established session to 203.0.113.50:443".
4. Injected/hollowed code often has **no loaded-module entry** (it was mapped manually, not via the loader), so `dlllist` doesn't list it. `windows.ldrmodules` (unlinked modules) and `windows.malfind` (private, executable, unbacked regions) catch it — the subject of Day 25.
5. **Wrong or missing symbols** for that build (or a smeared/partial image), not "nothing ran". Confirm with `windows.info` (does it identify the build and fetch symbols?), check connectivity to the symbol server or supply symbols with `-s`, and cross-check with `psscan`.
6. Because the *questions* — what ran, what it loaded, what it held open, what it talked to — are **OS-agnostic**; only the **structures and symbol sources** differ (Windows uses PDB-derived ISF fetched by banner/GUID; Linux/macOS build ISF from kernel DWARF, Day 26). Volatility has 90+ Windows, ~59 Linux and ~23 macOS plugins for this reason.
7. **Yes.** Volatility 3 is pure Python and cross-platform; a Linux box analyses a Windows raw capture fine, fetching Windows symbols over the network. You need Windows (or its vendor tools) only to **acquire** that capture — not to analyse it. (What this particular lab box lacks is a *real capture*, not Windows.)
8. MemProcFS exposes memory as a **browsable filesystem** (processes as folders, netstat/handles/registry as files), so you explore with `ls`/`cat` and pivot without the plugin API. It still depends on the **same layer + symbol** machinery (and the Dokany/FUSE mount) — wrong symbols give empty or wrong folders just as they give empty plugin output.

</details>

---

## 📚 Further reading

- Volatility 3 documentation (https://volatility3.readthedocs.io): the plugin list, symbols, and the *Getting Started* guide
- Volatility Foundation (https://volatilityfoundation.org) and the Volatility 3 source (https://github.com/volatilityfoundation/volatility3)
- *The Art of Memory Forensics* (Ligh, Case, Levy, Walters) — chapters on processes, objects and networking
- MemProcFS wiki (https://github.com/ufrisk/MemProcFS/wiki) — the filesystem layout and plugins
- Volatility Workbench (https://www.osforensics.com/tools/volatility-workbench.html)
- SANS DFIR memory-forensics posters — the plugin-to-question mapping

---

## ⏭️ Tomorrow: Day 25

**Hunting malicious code in memory: injection, hollowing, shellcode.** Tools: **YARA**, **PE-sieve / HollowsHunter**, **Moneta**.
Today you listed what ran and what it loaded. Tomorrow you hunt the code that hides *inside* a legitimate process — injected regions, hollowed images and loose shellcode — with signatures and in-memory scanners.

---

<sub>Part of the <a href="../README.md">DFIR Daily</a> series · <a href="../CURRICULUM.md">Full 60-day curriculum</a> · For educational and authorised use only.</sub>
