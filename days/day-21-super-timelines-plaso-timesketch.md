# Day 21: Super Timelines: Building and Analysing

> **Phase 2: Windows Forensics** · **Level:** 🟡→🔴 Intermediate to Advanced · **Time:** ~4 hours (reading + labs) · **Posted:** 2026-10-18
>
> **Tools today:** 🛠️ Plaso (log2timeline, psort, pinfo) · 🛠️ Timeline Explorer · 🛠️ Timesketch

---

## 🎯 Learning objectives

By the end of today you will be able to:

1. Explain what a **super timeline** is, what each of its timestamps means, and when a targeted timeline is the better choice.
2. Build one with **Plaso** from a disk image and from a triage collection, choosing parsers, filters and shadow-copy options deliberately.
3. Inspect what was extracted (`pinfo`), tag and filter it (`psort`), and export it in the right format for **Timeline Explorer** and **Timesketch**.
4. Pivot through a timeline (on a file, a program, a time window, a tag) and recognise timestomping, log clearing and other gaps in it.
5. Check a timeline tool's output against its limits: deduplication, time resolution, and how it identified each source.

---

## Part 1: The lesson

Since Day 10 you've read WS-ALICE one artifact at a time: the `$MFT`, the registry, Prefetch and Amcache, LNK files, event logs, Sysmon, SRUM, browsers. Each answered a question; none showed the whole night. A **super timeline** puts every timestamp from every artifact into one sorted list, so that a download, the process it started, the registry key it set and the file it timestomped line up second by second, and so that **gaps** (a log that stops, a cleared log, a missing hour) stand out.

### 1.1 What a timeline event is

One artifact produces **many events**, one per timestamp it holds, and each timestamp has its own meaning (Plaso calls it the *timestamp description*):

| Artifact | Timestamps → events | What the time means |
|---|---|---|
| NTFS file (`$MFT`) | `$STANDARD_INFORMATION` and `$FILE_NAME`, each with **MACB**: modified, accessed, changed (MFT entry), born | Different things, and the `$SI` set is easy to fake (Day 10) |
| Event-log record | Created; written | When the event was logged, by the logging computer's clock |
| Registry key | Last written | When **any** value in the key last changed, not which one |
| Prefetch | Up to 8 last run times | Executions (Day 12) |
| Browser history | Visit time; download start and end | Page loads and downloads (Day 18) |
| LNK / Jump List | Target's MAC times, entry times | The target file's times when the link was written (Day 13) |

Reading a timeline means reading **what each line's time means**, not just its order. Three more cautions:

- **Clocks and zones.** Most Windows artifacts store UTC; some store local time (and some text logs have no zone at all); every source has its own clock, and a skewed clock or a changed system time (event 4616) moves everything it wrote.
- **Resolution.** FAT keeps 2-second times, `$MFT` 100 ns, many logs only seconds. Events "at the same time" may be milliseconds or seconds apart.
- **Absence is a finding.** A Security log that starts at 01:38, a cleared PowerShell log (event 104 or 1102), or no Prefetch for a program Sysmon saw running: each tells you something.

**Super vs targeted.** A super timeline of a full disk has millions of events, most of them Windows updating itself. Investigators usually build a **targeted** timeline first (selected artifacts, a time window), and the super timeline when they need context or don't know where to look.

### 1.2 How Plaso works

Plaso ("Plaso Langar Að Safna Öllu") is the standard open-source super-timeline engine. Its tools:

| Tool | Does |
|---|---|
| **log2timeline** | Extraction: opens the source with dfVFS (raw/E01/VMDK/VHD images, partitions, **shadow copies**, BitLocker with `--credential`, archives, directories), preprocesses it (host name, users, time zone from the registry), runs **parsers and plugins** on every file, and writes **events** into a storage file (`.plaso`, SQLite) |
| **pinfo** | What's in a storage file: how it was made, events per parser and data type, warnings, tags |
| **psort** | Analysis and output: filters (`date > DATETIME(...)`, `data_type is ...`, `tag contains ...`), time slices, **deduplication**, analysis plugins (tagging, sessionize, browser searches, domains), and output modules (`dynamic` CSV, `l2tcsv`, `json_line`, `xlsx`, `opensearch_ts` for Timesketch) |
| **psteal** | log2timeline + psort in one command |
| **image_export** | Copies files out of an image by path, extension or signature filter |

Choosing what to extract:

| Option | Use |
|---|---|
| `--parsers win7`, `win_gen`, `webhist`, `linux`, `macos`... | **Presets**: groups of parsers for a platform (`log2timeline --parsers list`) |
| `--parsers '!filestat'` | Everything **except** a parser. On a triage collection copied to your disk, `filestat` reports the times **of your copy**: leave it out. On a disk image, file-system times are evidence: keep them |
| `--artifact_filters WindowsEventLogs,WindowsPrefetchFiles,...` | Only the files that Forensic Artifacts definitions name (the same idea as KAPE targets, Day 9) |
| `-f FILTER_FILE` | Only paths listed in a filter file |
| `--vss_stores all`, `--no_vss`, `--partitions all` | Include every shadow copy (Day 20) or none; every partition |
| `-z TIME_ZONE` | Time zone for sources that store local time without one (not a display option) |

### 1.3 Working a timeline

1. **Start from what you know**: a file name, a program, an IP, an account, an alert time. Filter or `grep` for it, then **widen** around each hit (a time slice: `psort --slice`, `--slicer`).
2. **Tag** what matters (`psort --analysis tagging` with Plaso's `tag_windows.txt` labels executions, logons, failed logons, new services, cleared logs, downloads...) and filter on tags.
3. **Annotate** as you go: Timeline Explorer's tag column, Timesketch's stars, tags and comments. The notes become your report.
4. **Check the tool**:
   - `psort` **removes duplicate events** by default. A LNK file and the Jump List entry that holds a copy of it produce identical events; `-a` keeps them all.
   - `l2tcsv` has **one-second resolution** and fixed fields; prefer `dynamic` CSV.
   - Excel stops at 1,048,576 rows and rewrites dates it recognises: open timelines in Timeline Explorer, not Excel.
   - A parser that can't identify a file produces **nothing** for it. Check `pinfo`'s per-parser counts and warnings against what you collected.

**Anti-forensics in a timeline:** timestomping shows as `$SI` times that are older than the `$FN` times, or older than the file's own download (Lab 4); log clearing shows as event 1102/104 plus the absence of earlier records; a deleted shadow copy removes a whole layer of history (Day 20); a changed system clock shows as event 4616 and time going backwards between neighbouring records.

### 1.4 WS-ALICE, one timeline

The labs combine the course's WS-ALICE artifacts (registry, Prefetch, Amcache, LNK files, Jump Lists, ShellBags, event logs, Sysmon, Edge and Firefox) with the NTFS volume of Day 10, about 1,300 events. The night of 2026-09-29 then reads like this:

| UTC | What the timeline shows |
|---|---|
| 01:02:02–01:02:03 | Edge downloads `payload.ps1`; Sysmon 11/15 record the file and its Zone.Identifier; `$FN` and `$SI` "born" at 01:02:03.118 |
| 01:04:10–01:04:19 | Three failed network logons (administrator, admin, bob) from LAPTOP-7Q2K, 10.20.30.45 |
| 01:05:12 | PsExec's service (7045), Prefetch, Amcache |
| 01:12:46–01:15:38 | rclone: the PowerShell script block, 4688, Sysmon 1, Prefetch, BAM, the DNS query for `g.api.mega.co.nz` and the connection, the Amcache entry, the exit |
| 01:20:44 | A PowerShell script block sets `payload.ps1`'s `LastWriteTimeUtc`; 0.3 s later the `$MFT` records of `payload.ps1` and `svchost.exe` change: the **timestomping**, caught in the act |
| 01:21–01:22 | Persistence three ways: scheduled task (4698, 106), Run key (Sysmon 13, registry), service OneDriveSync (7045, registry) |
| 01:38:12 | The classic "Windows PowerShell" log is cleared (System event 104) |

---

## Part 2: Tools

Plaso builds the timeline; Timeline Explorer is for reading CSV timelines on a Windows analysis machine; Timesketch is for searching, annotating and sharing them in a team.

---

### 🛠️ Tool 1: Plaso (log2timeline, psort, pinfo)

| | |
|---|---|
| **What** | The open-source super-timeline engine: log2timeline extracts events from images, devices, directories and files with hundreds of parsers and plugins; psort filters, tags and exports them; pinfo describes storage files |
| **Why in DFIR** | One tool for nearly every artifact of this phase, from disk images (with partitions, shadow copies and BitLocker) to triage collections, with outputs for Timeline Explorer, Timesketch and scripts |
| **Platforms** | Linux, macOS, Windows (officially through **Docker**; packages for Ubuntu and Fedora; PyPI) |
| **Licence** | Apache 2.0 |
| **Home** | https://github.com/log2timeline/plaso · https://plaso.readthedocs.io |

#### Requirements

Python 3.10+ (for pip), several GB of RAM for large images, and disk space: storage files can be a sizeable fraction of the evidence they describe. The Plaso team recommends a release no older than six months.

#### Installation

```bash
# Linux/macOS, PyPI in a virtual environment (validated here: 20260720)
python3 -m venv ~/tools/plaso-venv
~/tools/plaso-venv/bin/pip install plaso==20260720
# Ubuntu, packaged release (GIFT PPA, per the Plaso docs)
sudo add-apt-repository universe && sudo add-apt-repository ppa:gift/stable
sudo apt update && sudo apt install plaso-tools
# Docker (Linux, macOS, Windows), per the Plaso docs
docker pull log2timeline/plaso
docker run -v /data/:/data log2timeline/plaso log2timeline --storage-file /data/evidences.plaso /data/evidences
```

#### Configuration

| Option | Meaning |
|---|---|
| `log2timeline --storage_file F.plaso SOURCE` | Extract from SOURCE (image, device, directory or file) into F.plaso |
| `--parsers EXPR` | Presets and parser names, with `!` to exclude (`--parsers 'win7,!filestat'`); `--parsers list` |
| `--artifact_filters NAMES`, `-f FILE` | Only what the named Forensic Artifacts definitions (or a filter file) describe |
| `--partitions all`, `--volumes all`, `--vss_stores all`, `--no_vss`, `--credential TYPE:DATA` | Which volumes; shadow copies; BitLocker/LUKS credentials |
| `--hashers md5,sha256`, `--yara_rules FILE` | Hash files / tag them with YARA matches |
| `--workers N`, `--process_memory_limit`, `--temporary_directory` | Resources |
| `--status_view none`, `-q`, `--logfile` | Quiet runs and logs |
| `psort -o FORMAT -w FILE STORAGE [FILTER]` | Export (`dynamic`, `l2tcsv`, `json_line`, `xlsx`, `opensearch_ts`...; `-o list`); `-w` is required |
| `--fields`, `--additional_fields`, `--output_time_zone` | Columns and display zone |
| `--slice DATETIME --slice_size MIN`, `--slicer` | Time windows around a moment or around each filter match |
| `--analysis tagging --tagging-file FILE`, `-a` | Tag events; include duplicates |
| `pinfo --sections events\|warnings\|sessions`, `--output_format json` | What was extracted |

#### Verify the installation

```bash
~/tools/plaso-venv/bin/log2timeline --version        # plaso - log2timeline version 20260720
```

#### First use

```bash
log2timeline --storage_file case.plaso --vss_stores all --partitions all disk.E01
pinfo case.plaso
psort -o dynamic -w case.csv case.plaso "date > DATETIME('2026-09-29T00:00:00') AND date < DATETIME('2026-09-30T00:00:00')"
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| Registry events show odd or missing key prefixes (`[\ControlSet001\...]`, NTUSER keys under `HKEY_CURRENT_USER\Software\Classes`) | Plaso (dfwinreg) identifies a hive by keys every real hive has (SYSTEM: `\Select`, `\Setup`, `\MountedDevices`; NTUSER: `\AppEvents`, `\Console`, `\Control Panel`...). The course's lab hives are minimal stand-ins, so it can't; real hives are fine. Always read the source-file column |
| A hive yields **nothing**, with a warning like `unable to retrieve root key ... unsupported security key signature` | The hive is damaged or not a real hive (see `sqlite3 F.plaso 'SELECT * FROM extraction_warning'`); try a registry tool with recovery (Day 11) |
| `pinfo` ends with `TypeError: '<' not supported between instances of 'WarningCount' and 'WarningCount'` | A pinfo 20260720 bug, when several files produce the same number of warnings: use `pinfo --output_format json` (or `--sections events`) |
| `ERROR: Output format: dynamic requires an output file` | Add `-w FILE` |
| "Implicit event filter date and time conversion is deprecated" | Write dates as `DATETIME('2026-09-29T01:00:00')` |
| `l2tcsv` prints a warning and waits 15 seconds | Expected (second-only times, fixed fields); prefer `-o dynamic` |
| Event counts in the CSV are lower than in pinfo | psort removed duplicates; add `-a` to keep them |
| Times on a copied collection all look like today | `filestat` read your copy's file times: exclude it (`--parsers '!filestat'`) |
| Runs out of memory or very slow | Fewer parsers (presets, artifact filters), more `--workers` only if RAM allows, `--process_memory_limit` |

---

### 🛠️ Tool 2: Timeline Explorer

| | |
|---|---|
| **What** | Eric Zimmerman's Windows viewer for large CSV and Excel files: column filters, searching, grouping, row tagging and sessions |
| **Why in DFIR** | The usual way to read the CSV output of KAPE modules, Eric Zimmerman's tools and Plaso on a Windows analysis machine, at sizes that break Excel |
| **Platforms** | **Windows only** (not run in this lesson's Linux labs) |
| **Licence** | Free; download from the author's site |
| **Home** | https://ericzimmerman.github.io/ |

#### Requirements

Windows 10 or 11 with the **.NET Desktop Runtime** version named on the download page; RAM in proportion to the CSV.

#### Installation

```powershell
# Download TimelineExplorer from https://ericzimmerman.github.io/ (or with Get-ZimmermanTools.ps1, Day 1), unzip, run
.\TimelineExplorer\TimelineExplorer.exe
```

#### Configuration

| Feature | Use |
|---|---|
| File > Open | CSV or Excel; several files open as tabs |
| Column header filters and the search box | Narrow to a host, a user, a path, a time range |
| Drag a column header to the grouping area | Group by source, event ID, user |
| The **Tag** column | Mark the lines that matter; filter on them later |
| Sessions | Save and reopen your filters and tags with the case |

#### Verify the installation

Open `work/night-l2t.csv` from Lab 6: the header row becomes columns and the line count matches the file.

#### First use

Export with psort for it: `-o l2tcsv` (17 fixed columns, one-second times) or, better, `-o dynamic` with the fields you want. Open the file, sort by date/time, filter `source` or `sourcetype`, and tag the lines of Lab 4's pivots.

#### Troubleshooting

| Symptom | Fix |
|---|---|
| Won't start | Install the .NET Desktop Runtime version the download page names |
| Times look shifted | The CSV is UTC (`psort` default); don't convert, note the zone in your report |
| Very slow on a huge CSV | Filter in psort first (time window, tags), or use Timesketch |
| Garbled characters | Export UTF-8 (psort's default) and open the original, not a copy saved by Excel |

---

### 🛠️ Tool 3: Timesketch

| | |
|---|---|
| **What** | Google's open-source web platform for collaborative timeline analysis: **sketches** (cases) holding several timelines, fast search on OpenSearch, stars, tags, comments, saved views, analyzers (including Sigma rules) and stories |
| **Why in DFIR** | Several analysts on one case, timelines from many hosts in one place, and searches that stay fast at millions of events. It imports Plaso storage files, CSV and JSONL |
| **Platforms** | A server running Docker (Linux); used from a browser; clients with Python (`timesketch-import-client`, `timesketch-api-client`) |
| **Licence** | Apache 2.0 |
| **Home** | https://timesketch.org · https://github.com/google/timesketch |

#### Requirements

A Linux server (or VM) with Docker and the Docker Compose plugin, root access, and memory for OpenSearch (the installer sizes it from the machine's RAM; plan several GB). Not run here: this lab environment has no Docker daemon and can't reach the Timesketch image registry; the importer client was installed and checked.

#### Installation

```bash
# On the server, per the Timesketch install guide
curl -s -O https://raw.githubusercontent.com/google/timesketch/master/contrib/deploy_timesketch.sh
chmod 755 deploy_timesketch.sh
cd /opt && sudo ~/deploy_timesketch.sh          # creates /opt/timesketch (sets vm.max_map_count for OpenSearch)
cd /opt/timesketch && sudo docker compose up -d
sudo docker compose exec timesketch-web tsctl create-user analyst1
# On your workstation: the importer client (validated here: 20261014)
python3 -m venv ~/tools/ts-venv && ~/tools/ts-venv/bin/pip install timesketch-import-client==20261014
```

The installer prints that it runs **without TLS** by default: set up HTTPS before real use (https://timesketch.org/guides/admin/https/).

#### Configuration

| Option | Meaning |
|---|---|
| `timesketch_importer --host URL -u USER --pwd-prompt` | Server and account (credentials are then kept in `~/.timesketchrc` and a token file) |
| `--sketch_id N` or `--sketch_name NAME` | Which sketch (case) to add the timeline to |
| `--timeline_name NAME` | Name shown in the sketch (one per host or source) |
| `--plaso-event-filter FILTER` | Import only part of a `.plaso` file |
| `--analyzer_names ...` | Run analyzers after import |
| `--quick` | Don't wait for indexing to finish |

#### Verify the installation

```bash
~/tools/ts-venv/bin/timesketch_importer --version     # Importer Client Version: 20261014
```

On the server, `docker compose ps` shows the web, worker, OpenSearch, PostgreSQL and Redis containers running, and the web page opens.

#### First use

```bash
timesketch_importer --host https://timesketch.example.org -u analyst1 --pwd-prompt \
  --sketch_name "WS-ALICE" --timeline_name "WS-ALICE collection" work/collection.plaso
```

In the sketch, search `rclone`, star the hits, add the `payload.ps1` events to a saved view, and add the NTFS image's timeline next to it: Timesketch searches both together.

#### Troubleshooting

| Symptom | Fix |
|---|---|
| OpenSearch container restarts | `vm.max_map_count` too low (`sysctl -w vm.max_map_count=262144`) or too little memory |
| Import stays "processing" | Check `docker compose logs timesketch-worker`; large Plaso files take a while |
| Login fails from the importer | `--re-prompt` to re-enter host, user and password |
| Browser warnings / passwords in clear | It's HTTP by default: configure TLS |

---

## Part 3: Hands-on labs

One timeline of WS-ALICE from everything the course has generated so far: the artifacts of Days 11 to 18, assembled into a KAPE-style collection by `mk_alice_collection.py`, and the NTFS volume of Day 10 (`mk_ntfs_case10.sh`). Plaso and the Timesketch importer are pinned; `tl_view.py` prints timelines compactly in a terminal (Timeline Explorer and Timesketch do the same job graphically).

Run on Ubuntu 24.04 or SIFT (Plaso needs Python 3.10+). Building the NTFS image needs `sudo` (it mounts the volume).

```bash
sudo apt update && sudo apt install -y git python3-venv ntfs-3g faketime sqlite3
git -C ~/DFIR pull 2>/dev/null || git clone https://github.com/Mr-Phoenix07/DFIR.git ~/DFIR
mkdir -p ~/cases/LAB-021/{evidence,work,notes} ~/tools && cd ~/cases/LAB-021
export TZ=UTC
```

Install Plaso and the Timesketch importer in virtual environments (a few minutes):

```bash
[ -d ~/tools/plaso-venv ] || python3 -m venv ~/tools/plaso-venv
~/tools/plaso-venv/bin/pip install -q plaso==20260720 2> /dev/null
[ -d ~/tools/ts-venv ] || python3 -m venv ~/tools/ts-venv
~/tools/ts-venv/bin/pip install -q timesketch-import-client==20261014 2> /dev/null
log2timeline() { ~/tools/plaso-venv/bin/log2timeline "$@"; }
psort() { ~/tools/plaso-venv/bin/psort "$@"; }
pinfo() { ~/tools/plaso-venv/bin/pinfo "$@"; }
log2timeline --version
psort --version
~/tools/ts-venv/bin/timesketch_importer --version
```

```
plaso - log2timeline version 20260720
plaso - psort version 20260720
API Client Version: 20261014
Importer Client Version: 20261014
```

### Lab 1: The evidence (10 min)

```bash
python3 ~/DFIR/scripts/mk_alice_collection.py evidence/WS-ALICE
sudo bash ~/DFIR/scripts/mk_ntfs_case10.sh evidence/ntfs10.img > /dev/null
sudo chown $(id -u):$(id -g) evidence/ntfs10.img
(cd evidence && find WS-ALICE -type f | LC_ALL=C sort | xargs -d '\n' sha256sum | cut -c1-16,65- > ../notes/collection.sha256)
wc -l < notes/collection.sha256
sha256sum evidence/ntfs10.img | cut -c1-16,65-
```

```
37 files under evidence/WS-ALICE/C
37
fec841897e7cc3cc  evidence/ntfs10.img
```

37 files in the collection, hashed into your notes; the NTFS image has the same SHA-256 as on Day 10 (`fec84189...`), because the build is deterministic.

### Lab 2: Extract, and check what was extracted (20 min)

Two sources, two storage files. On the copied collection, leave out `filestat` (its file times are your copy's); on the image, keep everything:

```bash
log2timeline --status_view none -q --parsers '!filestat' --storage_file work/collection.plaso evidence/WS-ALICE > work/l2t-collection.log 2>&1
log2timeline --status_view none -q --storage_file work/ntfs10.plaso evidence/ntfs10.img > work/l2t-ntfs10.log 2>&1
pinfo --sections events work/collection.plaso | sed -n '/per data type/,/Total/p'
pinfo --sections events work/ntfs10.plaso | sed -n '/per parser/,/Total/p'
sqlite3 -readonly work/collection.plaso 'SELECT parser_chain, message FROM extraction_warning;'
```

```
************************ Events generated per data type ************************
                            Data type name : Number of events
--------------------------------------------------------------------------------
                     chrome:autofill:entry : 4
                       chrome:cookie:entry : 6
            chrome:history:file_downloaded : 2
               chrome:history:page_visited : 7
                      firefox:cookie:entry : 6
                firefox:downloads:download : 2
               firefox:places:page_visited : 6
                     olecf:dest_list:entry : 9
windows:distributed_link_tracking:creation : 26
                       windows:evtx:record : 162
                          windows:lnk:link : 45
                windows:prefetch:execution : 4
                  windows:registry:amcache : 2
                windows:registry:key_value : 76
                  windows:registry:mrulist : 1
                  windows:registry:service : 2
             windows:shell_item:file_entry : 138
                   windows:volume:creation : 2
                                     Total : 500
************************* Events generated per parser **************************
Parser (plugin) name : Number of events
--------------------------------------------------------------------------------
            filestat : 220
                 mft : 602
               Total : 822
winreg/amcache|missing LinkDate value data in key: \Root\InventoryApplicationFile\rclone.exe|7b39c6bb90da0f4b
```

- **500 events** from 37 files: 162 event-log records, 138 shell items (from LNK files and Jump Lists), 76 registry key/value events, browsers, Prefetch, Amcache, services.
- The image gave **822**: 220 from `filestat` and 602 from the `mft` parser, which reads `$MFT` records and reports `$STANDARD_INFORMATION` and `$FILE_NAME` times separately.
- One warning: the Amcache entry for rclone has no `LinkDate` value. Warnings are where a timeline silently loses data, so read them.

### Lab 3: Tag it (10 min)

```bash
TAGS=$(~/tools/plaso-venv/bin/python -c 'import os, plaso; print(os.path.join(os.path.dirname(plaso.__file__), "data", "tag_windows.txt"))')
grep -c '^[a-z]' $TAGS
psort --status_view none -q --analysis tagging --tagging-file $TAGS -o null work/collection.plaso > /dev/null
pinfo --sections events work/collection.plaso | sed -n '/per label/,/Total/p'
```

```
27
************************ Event tags generated per label ************************
                Label : Number of event tags
--------------------------------------------------------------------------------
application_execution : 26
        document_open : 1
     eventlog_cleared : 2
        file_download : 2
        login_attempt : 6
         login_failed : 6
               logoff : 2
          service_new : 4
             shutdown : 4
         system_start : 6
        task_schedule : 2
                Total : 61
```

Plaso's Windows tagging file defines 27 labels (each with one or more rules). They tagged 61 events: executions, logons and failed logons, new services, scheduled tasks, shutdowns and starts, downloads, and **cleared event logs**. Tags are a starting point: the one `document_open` tag is alice's RunMRU entry `powershell -w hidden -nop`, which the rule counts as a "document" because it doesn't end in `.exe`.

### Lab 4: Pivot on a file (20 min)

Export both storage files and follow `payload.ps1` through every source:

```bash
F=datetime,timestamp_desc,source,source_long,message,display_name,tag
psort --status_view none -q -o dynamic --fields $F -w work/collection.csv work/collection.plaso > /dev/null
psort --status_view none -q -o dynamic --fields $F -w work/ntfs10.csv work/ntfs10.plaso > /dev/null
psort --status_view none -q -a -o dynamic --fields $F -w work/collection-all.csv work/collection.plaso > /dev/null
wc -l work/collection.csv work/collection-all.csv work/ntfs10.csv
tl() { python3 ~/DFIR/scripts/tl_view.py work/collection.csv work/ntfs10.csv "$@" | cut -c1-140; }
tl --grep 'payload\.ps1'
```

```
   474 work/collection.csv
   501 work/collection-all.csv
   823 work/ntfs10.csv
  1798 total
2019-03-14 10:00:00.000  FILE    MA..        $SI \Users\alice\Downloads\payload.ps1  (MFT 114-1)
2019-03-14 10:00:00.000  FILE    MA..        file \Users\alice\Downloads\payload.ps1
2026-09-29 01:02:02.874  WEBHIST start       http://203.0.113.50/payload.ps1 (C:\Users\alice\Downloads\payload.ps1). State: Complete. Receiv
2026-09-29 01:02:03.118  FILE    MACB        $FN \Users\alice\Downloads\payload.ps1  (MFT 114-1)
2026-09-29 01:02:03.118  FILE    ...B        $SI \Users\alice\Downloads\payload.ps1  (MFT 114-1)
2026-09-29 01:02:03.118  FILE    ...B        file \Users\alice\Downloads\payload.ps1
2026-09-29 01:02:03.120  EVT     recorded    EVTX 11 Sysmon: Downloads; 2026-09-29 01:02:03.118; C:\Program Files (x86)\Microsoft\Edge\Appli
2026-09-29 01:02:03.126  WEBHIST end         http://203.0.113.50/payload.ps1 (C:\Users\alice\Downloads\payload.ps1). State: Complete. Receiv
2026-09-29 01:02:03.127  EVT     recorded    EVTX 15 Sysmon: 2026-09-29 01:02:03.121; C:\Program Files (x86)\Microsoft\Edge\Application\msed
2026-09-29 01:20:44.620  EVT     recorded    EVTX 4104 PowerShell: $p = Get-Item "$env:USERPROFILE\Downloads\payload.ps1" $p.LastWriteTimeUt
2026-09-29 01:20:44.903  FILE    ..C.        $SI \Users\alice\Downloads\payload.ps1  (MFT 114-1)
2026-09-29 01:20:44.903  FILE    ..C.        file \Users\alice\Downloads\payload.ps1
```

- psort wrote **473** rows for the collection's 500 events: it removed 27 **duplicates** (a LNK file and the Jump List entry that contains a copy of it produce the same events). `-a` keeps them all: 500.
- Read the `payload.ps1` lines in order: the browser downloaded it at 01:02:02–03, Sysmon logged the file and its Zone.Identifier, and its `$FN` record says **born 01:02:03.118, all four times**. Its `$SI` says **modified and accessed 2019-03-14**, seven years before it existed. Then, at 01:20:44.620, a PowerShell script block sets its `LastWriteTimeUtc`, and 0.3 s later its `$SI` "changed" time is updated. That's the timestomping, with the command that did it.

### Lab 5: Pivot on a time window (25 min)

rclone's first run:

```bash
tl --from 2026-09-29T01:12:46 --to 2026-09-29T01:15:39
```

```
2026-09-29 01:12:46.992  EVT     recorded    EVTX 4104 PowerShell: & $env:TEMP\rc\rclone.exe copy C:\Users\alice\Documents remote:drop --con
2026-09-29 01:12:47.662  EVT     recorded    EVTX 4688 Security-Auditing: alice; WS-ALICE; C:\Users\alice\AppData\Local\Temp\rc\rclone.exe; 
2026-09-29 01:12:47.662  LOG     earlier run Prefetch [RCLONE.EXE] was executed - run count 3 path hints: \USERS\ALICE\APPDATA\LOCAL\TEMP\RC
2026-09-29 01:12:47.662  REG     key written [\ControlSet001\Services\bam\State\UserSettings\S-1-5-21-3623811015-3361044348-30300820-1001] S
2026-09-29 01:12:47.664  EVT     recorded    EVTX 1 Sysmon: 2026-09-29 01:12:47.662; C:\Users\alice\AppData\Local\Temp\rc\rclone.exe; 1.68.2
2026-09-29 01:12:48.401  EVT     recorded    EVTX 22 Sysmon: 2026-09-29 01:12:48.390; g.api.mega.co.nz; ::ffff:198.51.100.77;; C:\Users\alic
2026-09-29 01:12:48.552  EVT     recorded    EVTX 3 Sysmon: Usermode; 2026-09-29 01:12:48.512; C:\Users\alice\AppData\Local\Temp\rc\rclone.e
2026-09-29 01:12:49.774  REG     key written [\Root\InventoryApplicationFile\rclone.exe|7b39c6bb90da0f4b] BinFileVersion: [REG_SZ] 1.68.2  B
2026-09-29 01:15:38.209  EVT     recorded    EVTX 5 Sysmon: 2026-09-29 01:15:38.207; C:\Users\alice\AppData\Local\Temp\rc\rclone.exe; WS-ALI
```

Eight sources within three seconds: the PowerShell command line (4104), then the process creation (4688 and Sysmon 1), Prefetch's run time and the BAM key, which agree to the millisecond (01:12:47.662), the DNS query for `g.api.mega.co.nz` (Sysmon 22) and the connection to 198.51.100.77 (Sysmon 3), and the Amcache entry two seconds later; the process exits at 01:15:38 (Sysmon 5). (Prefetch's "earlier run" is one of its previous run times: the last run was after the reboot, at 07:58:21.)

The persistence minutes, without the empty parent-key lines:

```bash
tl --from 2026-09-29T01:20:44 --to 2026-09-29T01:22:12 | grep -v -E 'key written \[\\(Root|ControlSet001\\Services)?\]|\(empty\)'
```

```
2026-09-29 01:20:44.620  EVT     recorded    EVTX 4104 PowerShell: $p = Get-Item "$env:USERPROFILE\Downloads\payload.ps1" $p.LastWriteTimeUt
2026-09-29 01:20:44.903  FILE    ..C.        $FN \Users\alice\AppData\Local\Temp\svchost.exe  (MFT 73-2)
2026-09-29 01:20:44.903  FILE    M.C.        $SI \Users\alice\AppData\Local\Temp  (MFT 71-1)
2026-09-29 01:20:44.903  FILE    ..C.        $SI \Users\alice\AppData\Local\Temp\svchost.exe  (MFT 73-2)
2026-09-29 01:20:44.903  FILE    ..C.        $SI \Users\alice\Downloads\payload.ps1  (MFT 114-1)
2026-09-29 01:20:44.903  FILE    M.C.        file \Users\alice\AppData\Local\Temp
2026-09-29 01:20:44.903  FILE    ..C.        file \Users\alice\AppData\Local\Temp\svchost.exe
2026-09-29 01:20:44.903  FILE    ..C.        file \Users\alice\Downloads\payload.ps1
2026-09-29 01:21:04.302  EVT     recorded    EVTX 4104 PowerShell: schtasks /create /tn OneDriveUpdate /xml $env:TEMP\rc\task.xml
2026-09-29 01:21:05.118  EVT     recorded    EVTX 4688 Security-Auditing: alice; WS-ALICE; C:\Windows\System32\schtasks.exe; "C:\Windows\sys
2026-09-29 01:21:05.120  EVT     recorded    EVTX 1 Sysmon: 2026-09-29 01:21:05.118; C:\Windows\System32\schtasks.exe; 10.0.26100.1 (WinBuil
2026-09-29 01:21:05.440  EVT     recorded    EVTX 4698 Security-Auditing: alice; WS-ALICE; \OneDriveUpdate; <?xml version="1.0" encoding="UT
2026-09-29 01:21:05.442  EVT     recorded    EVTX 11 Sysmon: T1053; 2026-09-29 01:21:05.440; C:\Windows\System32\svchost.exe; C:\Windows\Sys
2026-09-29 01:21:05.442  EVT     recorded    EVTX 106 TaskScheduler: \OneDriveUpdate; WS-ALICE\alice
2026-09-29 01:21:29.887  EVT     recorded    EVTX 4104 PowerShell: C:\Users\alice\AppData\Local\Temp\rc\rclone.exe copy C:\Users\alice\Docum
2026-09-29 01:21:29.893  EVT     recorded    EVTX 13 Sysmon: T1060 RunKey; SetValue; 2026-09-29 01:21:29.891; C:\Windows\System32\WindowsPow
2026-09-29 01:21:30.187  REG     key written [HKEY_CURRENT_USER\Software\Classes\Software\Microsoft\Windows\CurrentVersion\Run] OneDrive: [R
2026-09-29 01:22:09.880  EVT     recorded    EVTX 4104 PowerShell: sc.exe create OneDriveSync binPath= "C:\Users\alice\AppData\Local\Temp\rc
2026-09-29 01:22:10.499  EVT     recorded    EVTX 4688 Security-Auditing: alice; WS-ALICE; C:\Windows\System32\sc.exe; "C:\Windows\system32\
2026-09-29 01:22:10.501  EVT     recorded    EVTX 1 Sysmon: 2026-09-29 01:22:10.499; C:\Windows\System32\sc.exe; 10.0.26100.1 (WinBuild.1601
2026-09-29 01:22:10.555  EVT     recorded    EVTX 7045 Service Control Manager: OneDriveSync; C:\Users\alice\AppData\Local\Temp\rc\rclone.ex
2026-09-29 01:22:10.555  REG     key written [\ControlSet001\Services\OneDriveSync] Type: Service - Own Process (0x10) Start: Auto Start (2)
2026-09-29 01:22:10.557  EVT     recorded    EVTX 13 Sysmon: T1031 T1050; SetValue; 2026-09-29 01:22:10.555; C:\Windows\System32\services.ex
2026-09-29 01:22:11.200  EVT     recorded    EVTX 1 Sysmon: 2026-09-29 01:22:11.198; C:\Users\alice\AppData\Local\Temp\rc\rclone.exe; 1.68.2
2026-09-29 01:22:11.201  EVT     recorded    EVTX 7036 Service Control Manager: OneDrive Sync Helper; running; 4F004E00450044005200490056004
2026-09-29 01:22:11.213  EVT     recorded    EVTX 4688 Security-Auditing: alice; WS-ALICE; C:\Windows\System32\sc.exe; "C:\Windows\system32\
2026-09-29 01:22:11.230  EVT     recorded    EVTX 1 Sysmon: 2026-09-29 01:22:11.021; C:\Windows\System32\sc.exe; 10.0.26100.1 (WinBuild.1601
2026-09-29 01:22:11.302  LOG     earlier run Prefetch [RCLONE.EXE] was executed - run count 3 path hints: \USERS\ALICE\APPDATA\LOCAL\TEMP\RC
2026-09-29 01:22:11.639  EVT     recorded    EVTX 5 Sysmon: 2026-09-29 01:22:11.637; C:\Users\alice\AppData\Local\Temp\rc\rclone.exe; NT AUT
```

The timestomping at 01:20:44 (now also `svchost.exe` and the `Temp` folder), then the scheduled task (4104 → 4688/Sysmon 1 → 4698 → Sysmon 11 → Task Scheduler 106), the Run key (4104 → Sysmon 13 → the registry key's last-written time) and the service (4104 → 4688 → 7045 → the Services key → Sysmon 13 → the service starting rclone). Each step is confirmed by two or three independent sources.

### Lab 6: Tags, and exports for the other tools (15 min)

The tagged events that aren't executions:

```bash
tl --tag 'login_failed|service_new|eventlog_cleared|document_open'
```

```
2026-09-29 01:04:10.221  EVT     recorded    EVTX 4625 Security-Auditing: administrator; WS-ALICE; NtLmSsp; NTLM; LAPTOP-7Q2K; 10.20.30.45
2026-09-29 01:04:14.883  EVT     recorded    EVTX 4625 Security-Auditing: admin; WS-ALICE; NtLmSsp; NTLM; LAPTOP-7Q2K; 10.20.30.45
2026-09-29 01:04:19.337  EVT     recorded    EVTX 4625 Security-Auditing: bob; WS-ALICE; NtLmSsp; NTLM; LAPTOP-7Q2K; 10.20.30.45
2026-09-29 01:05:12.731  EVT     recorded    EVTX 7045 Service Control Manager: PSEXESVC; %SystemRoot%\PSEXESVC.exe; user mode service; dema
2026-09-29 01:09:31.442  REG     key written [HKEY_CURRENT_USER\Software\Classes\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU] 
2026-09-29 01:22:10.555  EVT     recorded    EVTX 7045 Service Control Manager: OneDriveSync; C:\Users\alice\AppData\Local\Temp\rc\rclone.ex
2026-09-29 01:38:12.330  EVT     recorded    EVTX 104 Eventlog: alice; WS-ALICE; Windows PowerShell
```

The failed logons that preceded the PsExec logon, both new services, and at 01:38:12 the **cleared "Windows PowerShell" log** (the classic log; the PowerShell/Operational log with the 4104 script blocks survived). That's a gap to account for: whatever the classic log held is gone, so look for the same activity in other sources.

Exports for Timeline Explorer and Timesketch:

```bash
psort --status_view none -q -o l2tcsv -w work/night-l2t.csv work/collection.plaso \
  "date > DATETIME('2026-09-29T00:55:00') AND date < DATETIME('2026-09-29T01:40:00')" > /dev/null 2>&1
head -n 1 work/night-l2t.csv
wc -l < work/night-l2t.csv
psort --status_view none -q -o json_line -w work/collection.jsonl work/collection.plaso > /dev/null
wc -l < work/collection.jsonl
python3 -c 'import json, sys; r = json.loads(open(sys.argv[1]).readline()); print(sorted(k for k in r if not k.startswith("_"))[:12])' work/collection.jsonl
```

```
date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra
139
473
['company_name', 'data_type', 'date_time', 'display_name', 'file_identifier', 'file_size', 'file_version', 'filename', 'full_path', 'message', 'parser', 'pathspec']
```

- `night-l2t.csv` is the night (00:55–01:40) in `l2tcsv` layout, the 17 columns Timeline Explorer and many older tools know; 138 events plus the header. psort warns about its limits (one-second times, fixed fields) and pauses 15 seconds first: for anything new, prefer `dynamic`.
- `collection.jsonl` has one JSON object per event (473), with every attribute: what Timesketch (or your own scripts) can import. Timesketch also imports the `.plaso` file directly.
- Not run here: open `night-l2t.csv` in Timeline Explorer on Windows, and import `work/collection.plaso` and `work/ntfs10.plaso` into one Timesketch sketch (Part 2).

---

## ✅ Knowledge check

1. A super timeline has three lines for the same file at 01:02:03.118 and two at 2019-03-14. What do you need to know about each line to read them correctly?
2. Why exclude `filestat` when processing a triage collection, but keep it for a disk image?
3. `pinfo` reports 500 events, but the CSV from psort has 473 rows. Why, and how do you get all 500?
4. A file's `$FN` times are 2026-09-29 and its `$SI` modified time is 2019-03-14. What happened, and what else in the timeline would confirm it?
5. Plaso produced no events at all from one registry hive. Where do you look, and what are two possible reasons?
6. Why is `l2tcsv` a poor choice for a new analysis, and what would you use instead?
7. What does Timesketch add over a CSV in Timeline Explorer?
8. You find event 104 (log cleared) at 01:38. What does that tell you, and what does it not tell you?

<details>
<summary><b>Answers</b></summary>

1. For each line: **which artifact** wrote it (`$FN`, `$SI`, file stat, browser, Sysmon...) and **what that time means** (born, modified, accessed, MFT changed; a download start; a record written). The same moment can appear several times from different sources; the 2019 times are `$SI` times, which can be set by software.
2. On a collection, the files are **copies** on your analysis disk: `filestat` would report when you copied them (and the generator's times), not the original volume's. On an image, `filestat` and `mft` read the **original file system**: those times are evidence.
3. psort **removes duplicate events** by default (identical timestamp and data, such as a LNK file and the Jump List entry that holds a copy of it). Add `-a` (`--include_all`).
4. The `$SI` times were **changed after creation** (timestomping): `$SI` is set through ordinary APIs, `$FN` is not. Confirm with: the `$SI` "changed" (MFT entry modified) time, the download or creation events (browser, Sysmon 11) that predate the claimed date, the command that did it (PowerShell 4104, Sysmon 1), and `$UsnJrnl` records (Day 10).
5. Look at `pinfo`'s per-parser counts and **warnings** (or `SELECT * FROM extraction_warning` in the storage file). Reasons: the hive is damaged or not a valid hive (libregf rejected it); it wasn't collected or was filtered out (`--parsers`, `--artifact_filters`); its format or key layout wasn't recognised.
6. **One-second** resolution and **17 fixed fields**, so it loses detail and attributes. Use `dynamic` CSV with the fields you need, or `json_line` / the `.plaso` file itself for Timesketch.
7. Search that stays fast at millions of events, **several timelines** (hosts, sources) in one sketch, **collaboration** (shared stars, tags, comments, saved views, stories), analyzers (including Sigma), and an audit trail of the analysis.
8. That someone with the right privileges **cleared that log** at 01:38 (and which account, in the event). It does not tell you what the log contained: look for the same events elsewhere (Sysmon, other logs, a SIEM, shadow copies, an earlier collection), and treat the missing period as a gap, not as "nothing happened".

</details>

---

## 📚 Further reading

- Plaso documentation (https://plaso.readthedocs.io): *User's Guide*, *Using log2timeline*, *Using psort*, *Event filters*, and the list of parsers and plugins
- OSDFIR blog: *Pearls and pitfalls of timeline analysis* (2021) and *Targeted timelines* (2013)
- Forensic Artifacts definitions (https://github.com/ForensicArtifacts/artifacts): the names `--artifact_filters` takes
- Timesketch documentation (https://timesketch.org): installation, the importer, search and analyzers
- Eric Zimmerman, *Timeline Explorer* (https://ericzimmerman.github.io/)

---

## ⏭️ Tomorrow: Day 22

**Windows persistence hunting.** Tools: **Autoruns**, **PersistenceSniper**, **Trawler**.
Today's timeline showed three persistence mechanisms in two minutes. Tomorrow: where Windows lets programs start themselves (well over a hundred places), and how to sweep them all on a live system and in an image.

---

<sub>Part of the <a href="../README.md">DFIR Daily</a> series · <a href="../CURRICULUM.md">Full 60-day curriculum</a> · For educational and authorised use only.</sub>
