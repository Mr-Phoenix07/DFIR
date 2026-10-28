# Day 26: Linux & macOS Memory Acquisition and Symbol Tables

> **Phase 3: Memory Forensics** · **Level:** 🔴 Advanced · **Time:** ~4 hours (reading + labs) · **Posted:** 2026-10-23
>
> **Tools today:** 🛠️ LiME · 🛠️ AVML · 🛠️ dwarf2json

---

## 🎯 Learning objectives

By the end of today you will be able to:

1. Acquire Linux (and Android) RAM with **LiME** (a kernel module) and **AVML** (a userland reader), and say when each fits.
2. Explain the **LiME format** — System RAM ranges with headers — and why it beats a flat/padded raw image for sparse memory.
3. State why Linux/macOS memory analysis has **no symbol server**, and build the **ISF** symbol table yourself with **dwarf2json**.
4. Go from an acquired image to analysis: extract the kernel **banner**, match or build the ISF, then run Volatility's `linux.*`/`mac.*` plugins.
5. Recognise the pitfalls — kernel-version mismatch, `kptr_restrict`, SIP/kext signing on macOS, and symbols-only vs full-type ISF.

---

## Part 1: The lesson

Phase 3 has been Windows-centric because that's where Volatility's symbols come for free. Linux and macOS are different in two ways that matter today: **how you acquire** RAM (no built-in imager; you bring a kernel module or a userland reader), and **how you get symbols** (there is no symbol server — you build the symbol table from the exact kernel yourself). Get either wrong and the analysis is dead on arrival.

### 1.1 Acquiring Linux RAM: module vs userland

- **LiME** is a **Loadable Kernel Module (LKM)**. You build it against the **running kernel's headers**, `insmod` it with a `path=` and `format=`, and it copies physical memory out with minimal userland interaction — the most forensically sound Linux method. The catch: it needs the matching kernel headers (or cross-build) and the ability to load a module (root, and not blocked by Secure Boot / lockdown / a container).
- **AVML** ("Acquire Volatile Memory for Linux", Microsoft) is a **static userland binary** — no module, no compiler on the target. It reads physical memory through whatever source is available, trying **`/proc/kcore`**, then **`/dev/crash`**, then **`/dev/mem`**, and writes the **LiME format**. Ideal for cloud/locked-down hosts where you can't build a module — but it depends on one of those sources being present and readable (many hardened kernels and containers expose none).

Both write the same container, so analysis is identical afterwards. (Android uses LiME too; macOS acquisition is harder — SIP and kext signing block most LKM-style tools, so practitioners lean on vendor/commercial acquirers or a vetted kext, and then analyse with Volatility's `mac` plugins and a dwarf2json-built ISF.)

### 1.2 The LiME format

A physical address space is **sparse**: "System RAM" sits in a few ranges with **holes** (reserved regions, MMIO) between them. Two ways to store that:

- **padded / raw** — fill from address 0, zeroing the holes. Simple, but huge and it throws away the map of what was really RAM.
- **LiME** — store only the System RAM ranges, each prefixed by a 32-byte header: magic `0x4C694D45` ("EMiL"), version, **s_addr**, **e_addr** (last byte, inclusive), 8 reserved bytes. The holes are simply **absent**, and every range keeps its true physical address.

Keeping the physical layout is what lets a framework translate virtual→physical correctly (Day 24). `lime_view.py` in the labs walks those headers; AVML can `convert` between LiME, compressed-LiME and raw.

### 1.3 The symbol problem: build your own ISF

Day 24's Windows path downloaded the matching symbols automatically from the Volatility symbol server. **For Linux and macOS there is no such server** — kernels are built by thousands of distros and versions, and the structure layouts differ with each. So you build the **ISF** (Intermediate Symbol Format: a JSON of types, symbols and enums) yourself, with **dwarf2json**, from the kernel you acquired:

- **Types** come from **DWARF debug info** — a `vmlinux` with symbols (e.g. a distro's `-dbgsym`/`debuginfo` package) fed to `dwarf2json linux --elf vmlinux`.
- **Symbols** (names→addresses) come from **DWARF**, from a **`System.map`**, or from **`/proc/kallsyms`** on the live host, via `--system-map`.

A full ISF needs the **types** (from DWARF); a `System.map`/`kallsyms`-only ISF has symbols but no types — enough for some lookups, not for walking `task_struct`. The workflow: acquire → read the **banner** (`Linux version …`) to identify the exact build → obtain that build's `vmlinux` debug info → `dwarf2json` → drop the JSON in Volatility's `symbols/linux/` → run `linux.pslist` and friends.

### 1.4 Pitfalls

- **Version mismatch.** An ISF must match the **exact** kernel build (version, config, compiler). The banner is the key; a near-miss gives wrong offsets, i.e. garbage.
- **`kptr_restrict`.** `/proc/kallsyms` may show all-zero addresses to non-root; read it as root (or set `kptr_restrict=0`) or the symbol addresses are useless.
- **No DWARF available.** Many production kernels ship no debug info; you may need to install the distro's debug package, or build symbols-only and accept reduced analysis.
- **macOS.** SIP and kext signing block LKM-style acquisition; plan for a vetted/commercial acquirer, and build the ISF from the kernel's DWARF (`dwarf2json mac --macho …`).
- **Containers/cloud.** No `/proc/kcore`, no `/dev/mem`, no module loading — acquisition must happen on the host/hypervisor, not inside the guest.

Today's labs **run dwarf2json for real** (building an ISF from this host's `kallsyms`), parse the **LiME format**, and use Volatility to pull the **banner** and to show the missing-symbol error. The **acquirers themselves don't run here** — this box can't load a kernel module (LiME) and has no `/proc/kcore`/`/dev/mem` for AVML — so those steps are documented.

---

## Part 2: Tools

**dwarf2json** runs here (Go). **LiME** needs the target's kernel headers and module loading; **AVML** needs `/proc/kcore`, `/dev/crash` or `/dev/mem` — neither is available in this container, so they're documented for a real host. `VER` is the version you fetch.

### 🛠️ Tool 1: LiME

| | |
|---|---|
| **What** | The Linux Memory Extractor — a loadable kernel module that dumps physical RAM to disk or over TCP. |
| **Why** | The most forensically sound Linux acquisition: minimal userland footprint, native **lime** format, works on Android. |

#### Requirements

- Linux/Android; **root**; the **kernel headers** for the running kernel (to build the `.ko`), or a cross-build for the target.
- Output space (file on another volume, or a network listener) ≥ System RAM.

#### Installation

```bash
# Build against the running kernel (Debian/Ubuntu)
sudo apt install -y build-essential linux-headers-$(uname -r) git
git clone https://github.com/504ensicsLabs/LiME
cd LiME/src && make           # produces lime-$(uname -r).ko
# Repo: https://github.com/504ensicsLabs/LiME
```

#### Configuration / first use

```bash
# Acquire to a file, lime format (keeps the physical range map):
sudo insmod ./lime-$(uname -r).ko "path=/mnt/evidence/ram.lime format=lime"
# Optional integrity sidecar and compression:
sudo insmod ./lime-$(uname -r).ko "path=/mnt/evidence/ram.lime format=lime digest=sha256 compress=1"
# Over the network (nothing written to the target's disk):
sudo insmod ./lime-$(uname -r).ko "path=tcp:4444 format=lime"
#   on the analyst host:  nc <target-ip> 4444 > ram.lime
sudo rmmod lime
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| `insmod: ERROR: could not insert module` | Headers don't match the running kernel, or Secure Boot/lockdown blocks unsigned modules; build against `linux-headers-$(uname -r)` or sign the module. |
| Need format for Volatility | Use `format=lime` (or `padded`); avoid `raw` (loses the physical map). |
| Acquiring Android | Cross-compile the module for the device kernel; see the repo's `docs`. |

### 🛠️ Tool 2: AVML

| | |
|---|---|
| **What** | Microsoft's "Acquire Volatile Memory for Linux" — a **static userland** acquirer that writes the LiME format, no kernel module required. |
| **Why** | Runs where you can't build/load a module (cloud VMs, minimal images); single portable binary; can compress and upload. |

#### Requirements

- Linux x86-64; **root** (to read physical memory). One readable source: **`/proc/kcore`**, **`/dev/crash`**, or **`/dev/mem`**.

#### Installation

```bash
# Prebuilt static binary (version VER) from releases:
#   https://github.com/microsoft/avml/releases     (then: chmod +x avml)
# Or build from source (Rust), static musl:
#   cargo build --release --target x86_64-unknown-linux-musl
```

#### Configuration / first use

```bash
sudo ./avml output.lime                       # acquire (auto-selects the source)
sudo ./avml --compress output.lime.compressed  # compressed LiME
sudo ./avml --source /proc/kcore output.lime   # force a source
./avml convert --source-format lime --format lime_compressed in.lime out.lime  # repack
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| "unable to open source" | None of `/proc/kcore`, `/dev/crash`, `/dev/mem` is present/readable (common in containers); acquire from the host/hypervisor instead. |
| Must run as non-root | Not possible — reading physical memory needs root. |
| Output won't load | It's LiME format; pass it straight to Volatility (or `convert` to raw). |

### 🛠️ Tool 3: dwarf2json

| | |
|---|---|
| **What** | The Volatility Foundation's Go tool that turns kernel **DWARF**/**System.map** into an **ISF** symbol table for Linux/macOS analysis. |
| **Why** | There is no Linux/macOS symbol server — this is how you *make* the symbols Volatility needs for a given kernel. |

#### Requirements

- Go (to build) on any OS. Inputs: a DWARF-bearing `vmlinux`/Mach-O (for types) and/or a `System.map`/`kallsyms` (for symbols).

#### Installation

```bash
git clone https://github.com/volatilityfoundation/dwarf2json
cd dwarf2json && go build          # produces ./dwarf2json
./dwarf2json --help
```

#### Configuration / first use

```bash
# Full ISF from a kernel with debug info (types + symbols):
./dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-$(uname -r) > kernel.json
# Symbols-only ISF from the live kernel's symbol table:
./dwarf2json linux --system-map /proc/kallsyms > symbols.json
# macOS:
./dwarf2json mac --macho kernel.dSYM/Contents/Resources/DWARF/kernel --macho-symbols kernel > mac.json
# Then place the JSON under Volatility's symbols/linux (or symbols/mac) directory.
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| ISF has 0 `user_types` | You gave only a `System.map`/`kallsyms` (symbols, no types); add a DWARF `vmlinux` with `--elf`. |
| Volatility still can't find symbols | The ISF must match the image's **banner** exactly, and live under the right `symbols/` subdir; check the banner with `banners.Banners`. |
| No `vmlinux`/debug info | Install the distro's `-dbgsym`/`debuginfo` for that kernel, or accept a symbols-only ISF. |

---

## Part 3: Hands-on labs

You work a Linux capture from the WS-ALICE campaign. A real LiME/AVML acquisition can't run here (no module loading, no `/proc/kcore`), so `mk_lime_sample.py` writes a small **real LiME-format** image to work with; `lime_view.py` reads its range map; Volatility pulls the **banner**; and **dwarf2json runs for real** to build an ISF from this host's live kernel symbols.

Run on Ubuntu/SIFT. Go and Python 3 are used; Volatility 3 is pinned (Day 24).

```bash
sudo apt update && sudo apt install -y git python3 python3-venv golang-go
git -C ~/DFIR pull 2>/dev/null || git clone https://github.com/Mr-Phoenix07/DFIR.git ~/DFIR
mkdir -p ~/cases/LAB-026/{evidence,work,notes} ~/tools && cd ~/cases/LAB-026
export TZ=UTC
export PATH="$PATH:/usr/local/go/bin"
[ -d ~/tools/vol-venv ] || python3 -m venv ~/tools/vol-venv
~/tools/vol-venv/bin/pip install -q volatility3==2.28.2 2> /dev/null
vol() { ~/tools/vol-venv/bin/vol "$@"; }
[ -x ~/tools/dwarf2json/dwarf2json ] || { git clone -q https://github.com/volatilityfoundation/dwarf2json ~/tools/dwarf2json && ( cd ~/tools/dwarf2json && go build 2>/dev/null ); }
d2j() { ~/tools/dwarf2json/dwarf2json "$@"; }
python3 ~/DFIR/scripts/mk_lime_sample.py evidence/linux.lime
vol --help 2>/dev/null | head -n 1
test -x ~/tools/dwarf2json/dwarf2json && echo "dwarf2json: built"
```

```
wrote evidence/linux.lime: 24640 bytes (2 ranges, 24576 bytes of System RAM + headers)
Volatility 3 Framework 2.28.2
dwarf2json: built
```

### Lab 1: Read the LiME range map (10 min)

LiME/AVML store System RAM as ranges, holes omitted. Walk the headers:

```bash
python3 ~/DFIR/scripts/lime_view.py evidence/linux.lime
```

```
evidence/linux.lime: 2 range(s), LiME version 1
  0x000000001000 - 0x000000004fff        16384 bytes
    -- gap: 1028096 bytes of non-System-RAM (0x5000..0xfffff) --
  0x000000100000 - 0x000000101fff         8192 bytes
  total System RAM: 24576 bytes in 2 range(s); file 24640 bytes
```

Two ranges with their true physical addresses and a **1 MB gap** between them — memory the hardware didn't map as System RAM, which a `padded`/raw image would have zero-filled into the file. Keeping that map is why `format=lime` is the right choice and why Volatility can translate addresses correctly.

### Lab 2: Identify the kernel from the image (10 min)

Before symbols, you need the exact build. Volatility's `banners` scans the image for the kernel version string — and it needs **no symbols** to do it:

```bash
vol -q -f evidence/linux.lime banners.Banners 2>/dev/null
```

```
Volatility 3 Framework 2.28.2

Offset	Banner

0x1100	Linux version 6.8.0-ws-alice (gcc version 13.2.0) #1 SMP PREEMPT_DYNAMIC Fri Oct 23 00:00:00 UTC 2026
```

There's the build — `Linux version 6.8.0-ws-alice …` at physical `0x1100` (inside the first range). That string is the **key**: it names the kernel whose ISF you must supply, and Volatility uses it to pick the matching symbol file.

### Lab 3: No symbols, no analysis (5 min)

Try to list processes without an ISF and read the (now familiar) refusal:

```bash
vol -q -f evidence/linux.lime linux.pslist 2>/dev/null | grep 'Unsatisfied requirement'
```

```
Unsatisfied requirement plugins.PsList.kernel.layer_name: 
Unsatisfied requirement plugins.PsList.kernel.symbol_table_name: 
```

Same two unmet requirements as Day 24's Windows case — but here Volatility **can't just download** the Linux symbols. You have to build them.

### Lab 4: Build the ISF with dwarf2json (15 min)

Make a symbol table from this host's live kernel (`/proc/kallsyms`) and inspect it. In a real case you'd use the acquired host's `vmlinux` debug info for a full, typed ISF — here `kallsyms` gives a symbols-only one, which is enough to see the machinery:

```bash
d2j linux --system-map /proc/kallsyms > work/kernel.isf.json 2>/dev/null
python3 -I ~/DFIR/scripts/isf_peek.py work/kernel.isf.json
```

```
work/kernel.isf.json
  producer: dwarf2json 0.9.0
  target: linux   sources: system-map
  base_types : 0
  user_types : 0
  enums      : 0
  symbols    : 128238
  completeness: symbols only (no types - add a DWARF vmlinux for full analysis)
```

dwarf2json produced a valid ISF: metadata naming the producer and source, and a symbol table — **128,238** symbols from this kernel (yours will differ with your kernel). `user_types` is `0` because `/proc/kallsyms` carries no type info; feed `dwarf2json` a DWARF `vmlinux` (`--elf`) for the types that let Volatility walk `task_struct` and run the full `linux.*` plugin set. Drop a matching, complete ISF in `symbols/linux/` and Lab 3's error turns into a process list.

---

## ✅ Knowledge check

1. Why can't you acquire Linux RAM the way Day 23 acquired Windows RAM, and what are the two main approaches instead?
2. LiME vs AVML: when would you reach for the userland tool over the kernel module?
3. What does the LiME format keep that a `padded`/raw image discards, and why does it matter for analysis?
4. Day 24 never ran dwarf2json for Windows. Why is it unavoidable for Linux/macOS?
5. You built an ISF from `/proc/kallsyms`; `isf_peek` shows `user_types: 0`. What can and can't you do with it, and how do you get the rest?
6. `linux.pslist` gives wrong/garbage output (not an error). What's the most likely cause, and how do you confirm the right symbols?
7. `/proc/kallsyms` shows `0000000000000000` for every symbol. What happened and how do you fix it?
8. You're told to acquire RAM from a compromised Docker container. What's the problem, and where do you acquire instead?

<details>
<summary><b>Answers</b></summary>

1. Windows ships/downloads its imager and symbols; Linux has neither built in. You bring either a **kernel module** (LiME — build against the running kernel, `insmod`) or a **userland reader** (AVML — a static binary reading `/proc/kcore`, `/dev/crash` or `/dev/mem`). Both write the LiME format.
2. Use **AVML** when you **can't build or load a module** — cloud VMs, minimal/locked-down images, no kernel headers, Secure Boot/lockdown. Use **LiME** when you can, for the smaller footprint and because it doesn't depend on a physical-memory device being exposed.
3. LiME keeps the **map of real System RAM ranges and their physical addresses**, omitting the holes; padded/raw zero-fills the holes from address 0 and loses which bytes were really RAM. The real physical layout is what lets the framework do **virtual→physical translation** correctly.
4. Windows has a **symbol server** Volatility queries by the image's PDB GUID. Linux/macOS have **no server** — kernels vary per distro/version/config — so you must **build the ISF yourself** with dwarf2json from that exact kernel's DWARF/System.map.
5. A **symbols-only** ISF resolves some **names↔addresses**, but without **types** you can't walk structures like `task_struct`, so `linux.pslist` won't work. Get the rest by feeding dwarf2json a **DWARF-bearing `vmlinux`** (`--elf`), e.g. from the distro's `-dbgsym`/debuginfo package for that build.
6. **The ISF doesn't match the exact kernel build** (wrong version/config → wrong offsets → garbage). Confirm by reading the image's **banner** (`banners.Banners`) and using the ISF built from precisely that `vmlinux`/System.map; a near-match is not a match.
7. **`kptr_restrict`** is hiding kernel pointers from your (non-root) read. Read `/proc/kallsyms` **as root** (or set `kptr_restrict=0`); otherwise the symbols-only ISF has useless (zero) addresses.
8. A container shares the **host kernel** and usually exposes **no `/proc/kcore`, `/dev/mem`, or module loading** — you can't image "the container's RAM" from inside it. Acquire from the **host (or hypervisor)**, where the physical memory and the kernel actually live.

</details>

---

## 📚 Further reading

- LiME (https://github.com/504ensicsLabs/LiME) — README and the `docs/` internals, formats and digests
- AVML (https://github.com/microsoft/avml) — sources, `acquire`/`convert`/`stream`/`upload`
- dwarf2json (https://github.com/volatilityfoundation/dwarf2json) and the Volatility 3 *Linux/Mac symbols* docs
- Volatility 3 symbols guide: building and placing ISF, and the `banners` plugin
- *The Art of Memory Forensics* — the Linux and Mac acquisition/analysis chapters

---

## ⏭️ Tomorrow: Day 27

**Hibernation files, pagefile & crash dumps.** Tools: **Hibernation Recon**, **bstrings**, **WinDbg**.
RAM isn't only in a live capture: Windows writes compressed memory to `hiberfil.sys`, swaps pages to `pagefile.sys`, and dumps state to crash dumps. Tomorrow we recover memory from those on-disk artifacts and read what they still hold.

---

<sub>Part of the <a href="../README.md">DFIR Daily</a> series · <a href="../CURRICULUM.md">Full 60-day curriculum</a> · For educational and authorised use only.</sub>
