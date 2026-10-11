# Day 13: File and Folder Knowledge: LNK Files, Jump Lists and ShellBags

> **Phase 2: Windows Forensics** · **Level:** 🟡 Intermediate · **Time:** ~3–4 hours (reading + labs) · **Posted:** 2026-10-10
>
> **Tools today:** 🛠️ LECmd · 🛠️ JLECmd · 🛠️ ShellBags Explorer (SBECmd)

---

## 🎯 Learning objectives

By the end of today you will be able to:

1. Explain what **LNK files**, **Jump Lists** and **ShellBags** are, where each lives, and what each **proves about a user's knowledge** of a file or folder.
2. Read an LNK file: the target's path, size and timestamps, the **volume serial number and type** (fixed, removable, network), the **MFT reference** and the **tracker block** (machine name, MAC address, object IDs).
3. Read a Jump List: the **AppID**, the DestList entries (last used, interaction count, pinned) and the LNK stream behind each entry.
4. Read ShellBags: the folder tree a user browsed, including **deleted folders, USB drives and network shares**, and which timestamps you can and can't trust.
5. Link the three into a timeline, and use object IDs and MFT references to recognise the **same file under a different name**.

---

## Part 1: The lesson

Yesterday's artifacts answered "what ran?". Today's answer **"what did the user know about?"**: which files they opened, which folders they browsed, and where those files and folders were (local disk, USB drive, network share), even after the files are deleted or the drive is gone. All three artifacts are written by the **Windows shell** (Explorer and the standard Open/Save dialogs) as a side effect of normal use, which is why they are such strong evidence of **user interaction**.

### 1.1 The three artifacts at a glance

| | **LNK files** (shell links) | **Jump Lists** | **ShellBags** |
|---|---|---|---|
| **Where** | `%APPDATA%\Microsoft\Windows\Recent\*.lnk` (plus Desktop, Start Menu and any shortcut a user or installer creates) | `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\<AppID>.automaticDestinations-ms` and `…\CustomDestinations\<AppID>.customDestinations-ms` | `UsrClass.dat`: `Local Settings\Software\Microsoft\Windows\Shell\BagMRU` and `\Bags` (some also in `NTUSER.DAT`: `Software\Microsoft\Windows\Shell\BagMRU`) |
| **Created when** | A file is opened through the shell (double-click, Open dialog) | An application opens a file (per-app "recent" list); the user pins an item | A folder is shown in Explorer or a file dialog (Windows saves its view settings) |
| **Tells you** | One target per file: path, volume, size, MACB times, MFT reference, machine/MAC | Per **application**: every file or folder it opened, last use time, count, pinned | Every **folder** browsed, as a tree: local, USB, network, ZIP, Control Panel, phones |
| **Survives deletion of the target?** | Yes | Yes | Yes |
| **Per user?** | Yes (in the profile) | Yes | Yes (in the user's hive) |
| **Format** | MS-SHLLINK (documented) | OLE compound file of LNK streams + `DestList` | Registry values holding **shell items** (the same structures as inside an LNK) |

They overlap on purpose: a file opened from a USB drive typically leaves a **Recent LNK**, an entry in the **application's Jump List**, and a **ShellBag** for the folder it was in. When they agree you have a strong finding; when one is missing, ask why (cleared, different user, opened from a command line…).

### 1.2 LNK files in depth

A shell link is a small binary file defined by Microsoft's **MS-SHLLINK** specification. It always starts with the 76-byte header `4C 00 00 00` followed by the CLSID `00021401-0000-0000-C000-000000000046`. Its parts:

```
+-------------------------+  76 bytes: flags, target attributes, target CREATED / ACCESSED / MODIFIED, target size
| ShellLinkHeader         |
+-------------------------+  shell items: My Computer > C:\ > Users > alice > ... (each folder/file item carries
| LinkTargetIDList        |  its own FAT-format times and, on NTFS, the MFT entry and sequence number)
+-------------------------+  volume: drive type (fixed/removable/network), SERIAL NUMBER, label, local path;
| LinkInfo                |  or network share: \\server\share + path suffix
+-------------------------+
| StringData              |  name, relative path, working directory, ARGUMENTS, icon location
+-------------------------+  TrackerDataBlock: MACHINE NAME + object IDs ("droids") holding a TIME and a MAC
| ExtraData blocks        |  address; property stores, known-folder and console blocks, ...
+-------------------------+
```

**Where Recent LNKs come from.** When a user opens a file through the shell, Windows creates or updates `Recent\<file name>.lnk` (and usually one for the containing folder too). Because the shortcut is named after the target, opening a different file **with the same name** from another folder typically **reuses** the existing `.lnk`, which then describes the newer target. Older Office versions also keep their own LNKs in `%APPDATA%\Microsoft\Office\Recent`.

**The timestamps, and what each means:**

| Time | Where it comes from | Meaning |
|---|---|---|
| `.lnk` file **created** | File system ($MFT) | First time a file with that name was opened (for Recent LNKs) |
| `.lnk` file **modified** | File system ($MFT) | Last time it was opened |
| Target **created / modified / accessed** | LNK header | The target's `$STANDARD_INFORMATION` times **at the last open** (an old snapshot if the file changed later) |
| Shell item times | Target ID list | FAT-format times (2-second resolution) captured when the ID list was built; can be **older** than the header (Lab 1) |
| Tracker "creation" | Object ID (version 1 GUID) | When the target was given an **object ID**, roughly the first time anything linked to it |

Copying LNK files with a tool that doesn't preserve file-system times loses the first two, so collect them with KAPE (Day 9) or read the times from the $MFT (Day 10).

**What the volume information gives you:** the **drive type** (`Fixed`, `Removable`, `Network`), the **volume serial number** (assigned when the volume is formatted; 8 hex digits) and the **volume label**. That's how you prove a file was opened **from a USB drive** that has since disappeared, and then match it to a seized drive or to the device history in the registry and event logs.

**The tracker block (Distributed Link Tracking).** NTFS lets Windows give a file an **object ID** so that shortcuts can find it again after it's moved. The TrackerDataBlock stores:

- **Machine ID**: the NetBIOS name of the machine the target lived on.
- **Volume and file droids**: the volume's and the file's object IDs, plus "birth" copies (the IDs when first assigned; they differ if the file later moved to another volume).
- The file droid is a **version 1 GUID**, which embeds a **timestamp** and the **MAC address** of the machine that created it. LECmd and JLECmd decode both.

An object ID **stays with the file when it's renamed**, so two LNKs with different paths but the same file droid (or the same MFT entry and sequence number) point to **the same file under two names**. You'll see that in Lab 3.

**Malicious LNKs.** Attackers send LNK files (in ZIP or ISO attachments) whose target is `cmd.exe` or `powershell.exe` with a long command line in the **arguments** field and a harmless-looking icon. The machine name, MAC address and volume serial in such an LNK often come from the attacker's **build machine**, and threat-intelligence teams use them to link campaigns. Always check `Arguments`, `Icon location` and the tracker block of shortcuts that arrive from outside.

### 1.3 Jump Lists in depth

Since Windows 7, the taskbar and Start menu show a **per-application list** of recent and pinned items. Windows stores it per user in two places:

| Folder | File | Contents |
|---|---|---|
| `Recent\AutomaticDestinations\` | `<AppID>.automaticDestinations-ms` | Maintained by Windows. An **OLE compound file** (the old Office `.doc` container) holding one **LNK stream** per item (named `1`, `2`, … in hex) and a **`DestList`** stream that indexes them |
| `Recent\CustomDestinations\` | `<AppID>.customDestinations-ms` | Written by applications that define their own lists (tasks, pinned or frequent items): LNK structures stored one after another |

**AppID.** The 16-hex-digit file name identifies the application. It's a hash of the application's identity (its AppUserModelID or path), so the same program run from another path, or a different version, can get a different AppID. JLECmd has a built-in list of known AppIDs (`--appIds` adds your own). Some you'll meet often:

| AppID | Application (as JLECmd names it) |
|---|---|
| `f01b4d95cf55d32a` | Windows Explorer (Windows 8.1 and later): folders opened, pinned Quick Access items |
| `9b9cdc69c1c24e2b` | Notepad 64-bit |
| `b8ab77100df80ab2` | Microsoft Office Excel x64 |
| `1b4dd67f29cb1962` | Windows Explorer pinned and recent (Windows 7) |

**DestList.** A 32-byte header (version: 1 on Windows 7/8, 3 or 4 on Windows 10/11; number of entries; number pinned; last entry number) followed by one entry per item:

| Field | Meaning |
|---|---|
| Entry number | Names the LNK stream that belongs to this entry |
| Volume and file droids, birth droids | Object IDs, as in the LNK tracker block (gives a **first linked** time and the MAC address) |
| Host name | NetBIOS name of the computer |
| **Last used** | FILETIME of the last time the app opened this item |
| **Pin status** | Pinned or not |
| **Interaction count** | How often it was used (Windows 10 and later) |
| Path | The item's path (or a `knownfolder:{GUID}` reference) |

**What Jump Lists add to LNK files:** *which application* opened the file, a **use count**, **pinning**, and history for files whose Recent LNK was overwritten or deleted. The `.automaticDestinations-ms` file's own creation time is roughly the first time that application ever used a file through the shell.

**Pitfalls:** Jump Lists keep the path the file had **when it was opened** and are not updated by renames, so the same file can appear under an old and a new name. Entries for network files often have **no object ID**: JLECmd then prints a creation time of `1582-10-15 00:00:00` (the zero point of version 1 GUIDs) and no MAC address, which means "unknown", not a real date.

### 1.4 ShellBags in depth

Explorer remembers how you like each folder displayed (icon size, sort order, window position). To do that it keeps, per user, a tree of every folder it has displayed: the **ShellBags**.

```
UsrClass.dat
└─ Local Settings\Software\Microsoft\Windows\Shell
   ├─ BagMRU                         values "0","1"…: one SHELL ITEM per child folder
   │  ├─ MRUListEx                   order of the children, most recent first
   │  ├─ NodeSlot                    which Bags\<n> key holds this folder's view settings
   │  ├─ 0  = My Computer            (root item 0x1F + GUID)
   │  │  ├─ 0 = C:\                  (volume item 0x2F)
   │  │  │  └─ 0 = Users > alice > … (folder items 0x31, with BEEF0004 extension blocks)
   │  │  └─ 1 = E:\ > finance        a USB drive, still listed after it was unplugged
   │  └─ 1  = Network > \\server > \\server\share   (network items 0x42 / 0xC3)
   └─ Bags\<n>\Shell\...             the view settings themselves
```

On Windows 7 and later most ShellBags are in `UsrClass.dat` (`C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat`); some desktop and network entries are in `NTUSER.DAT` under `Software\Microsoft\Windows\Shell`. Windows XP used `NTUSER.DAT\Software\Microsoft\Windows\ShellNoRoam`.

**What ShellBags prove:** the user's Explorer (or a file dialog) **displayed that folder**, at some point, with the path and type the shell items record: local, **removable** (by drive letter, plus the folder's MFT reference if the drive was NTFS), **network shares**, ZIP files opened as folders, Control Panel pages, phones and cameras (MTP). Entries remain after the folder is deleted, the drive is removed or the share is gone.

**What they don't prove:** that any particular **file** in the folder was opened (use LNK files and Jump Lists for that), or exactly *when* every folder was browsed.

**The timestamps, carefully:**

| Time | Source | Meaning |
|---|---|---|
| **MRU time** | The last-write time of the **parent** BagMRU key | When the child that is **first in `MRUListEx`** was last browsed. Only valid for that one child (Lab 5) |
| A folder's own key last-write time | `BagMRU\…\<n>` | Last time something changed below that folder's key: a good "last browsed" for leaf folders |
| Created / modified / accessed | Inside the shell item (BEEF0004 block) | The **folder's own** file-system times when the bag entry was **created**, at 2-second resolution. Not updated later |
| MFT entry / sequence | Inside the shell item | Identifies the folder on its NTFS volume; a different sequence number means a different folder with the same name |

**Anti-forensics.** Privacy cleaners delete BagMRU and Bags. Deleted keys and values can often be recovered from the hive's free space (Day 11: Registry Explorer shows them). Also check the other two artifacts: wiping ShellBags doesn't remove LNK files or Jump Lists.

### 1.5 Putting it together

| Question | First look at | Confirm with |
|---|---|---|
| Did the user open file X? When (first/last)? | Recent LNK (.lnk created/modified), Jump List last used | Office/application MRUs (Day 11), `$J` (Day 10) |
| With which application, how often? | Jump List (AppID, interaction count) | Prefetch run count for the application (Day 12) |
| Was it on a USB drive or a share? | LNK volume type/serial/label, network path | ShellBags for the folder, device history in the registry and event logs (Days 11, 14) |
| Did the user browse folder Y, even if it's gone? | ShellBags | Explorer Jump List, typed paths (Day 11) |
| Was file A renamed to B? | Same MFT entry/sequence or same object ID in two LNKs or Jump List entries | `$J` rename records, $MFT (Day 10) |
| Which machine created this LNK? (e.g., a phishing attachment) | Tracker block: machine ID, MAC, volume serial | Threat intelligence on other samples |

---

## Part 2: Tools

---

### 🛠️ Tool 1: LECmd

| | |
|---|---|
| **What** | Eric Zimmerman's LNK file parser |
| **Why in DFIR** | Decodes every part of a shell link: header times, target ID list (with MFT references), volume or network information, string data (arguments!), tracker block (machine name, MAC address and vendor, object IDs) and property stores, to the console or to CSV/JSON/XML/HTML |
| **Platforms** | Windows (.NET 9 and .NET 4.7.2 builds). **Built from source and run on Ubuntu 24.04** in this lesson |
| **Licence** | MIT |
| **Home** | https://github.com/EricZimmerman/LECmd · downloads: https://ericzimmerman.github.io |

#### Requirements

Windows 10/11 with the .NET 9 runtime (Day 1), or Linux with a .NET SDK (Ubuntu 24.04: `dotnet-sdk-10.0`). No administrator rights are needed to parse collected files.

#### Installation

```powershell
# Windows: with all EZ tools (Day 1)
C:\Tools\ZimmermanTools\Get-ZimmermanTools.ps1 -Dest C:\Tools\ZimmermanTools -NetVersion 9
C:\Tools\ZimmermanTools\net9\LECmd.exe --version
```

```bash
# Linux (validated here)
sudo apt install -y dotnet-sdk-10.0 git
git clone -q --depth 1 https://github.com/EricZimmerman/LECmd.git ~/tools/LECmd-src
dotnet publish ~/tools/LECmd-src/LECmd/LECmd.csproj -c Release -f net9.0 -o ~/tools/LECmd -v quiet > /dev/null
echo 'lecmd() { DOTNET_ROLL_FORWARD=Major ~/tools/LECmd/LECmd "$@"; }' >> ~/.bashrc
```

On Linux, `liblnk-utils` (`sudo apt install liblnk-utils`) gives you `lnkinfo`, an independent second parser. The Ubuntu 24.04 build (20181227) prints the target file size in its "Show Window" and "Hot Key" lines, so ignore those two.

#### Configuration

From `LECmd --help`:

| Option | Meaning |
|---|---|
| `-f FILE` / `-d DIR` | One file / a folder, recursively (only `*.lnk` unless you add `--all`, e.g. for LNKs carved or renamed during an investigation) |
| `-r` | Only LNK files that point to **removable drives** |
| `--csv DIR --csvf NAME` | CSV output (also `--json` with `--pretty`, `--xml`, `--html`) |
| `-q` | Quiet: no per-file details on screen (use with `--csv`) |
| `--nid`, `--neb` | Hide the target ID list / the extra blocks in the console output |
| `--dt FORMAT`, `--mp` | Timestamp format; higher precision |
| `--cp N` | Code page for non-Unicode strings (default 1252) |

LECmd also reports the **MAC vendor** for the tracker block from a built-in list.

#### Verify the installation

```bash
lecmd --version      # 2026.5.0+<commit> was used here
```

#### First use

```powershell
# A KAPE collection (Day 9): every user's Recent folder, Desktop and Start Menu shortcuts
LECmd.exe -d E:\Cases\WS-ALICE\tout\C\Users --csv E:\Cases\WS-ALICE\lnk -q
# Only the ones that pointed to USB drives
LECmd.exe -d E:\Cases\WS-ALICE\tout\C\Users -r --csv E:\Cases\WS-ALICE\lnk-usb -q
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| `has an invalid signature! Is it a valid LNK file?` | Not a shell link. A deleted shortcut's Recycle Bin `$I…lnk` file keeps the `.lnk` extension but holds only Recycle Bin metadata; the `$R…lnk` file is the shortcut (Day 17). Check the first 4 bytes are `4C 00 00 00` |
| `-d` skips files you know are LNKs | They don't end in `.lnk`. Add `--all` |
| "Source created" equals "Source modified", or shows the collection time | The LNK's own times come from the file system: the copy didn't keep them. Use KAPE's copy, or the $MFT |
| Target times look older than the last open | They're the target's times **as of the last open**; the target may have changed since. Shell item times can be older still |
| Absolute path of a network target shows the server twice | The share's shell item holds the full `\\server\share`; read the share from **NetworkPath** in the LinkInfo instead |

---

### 🛠️ Tool 2: JLECmd

| | |
|---|---|
| **What** | Eric Zimmerman's Jump List parser for `*.automaticDestinations-ms` and `*.customDestinations-ms` |
| **Why in DFIR** | Resolves the AppID, decodes the DestList (last used, interaction count, pinned, host name, object IDs) and fully parses each embedded LNK; exports CSV per type and can **dump the LNK streams** as ordinary `.lnk` files |
| **Platforms** | Windows (.NET 9 and .NET 4.7.2 builds). **Built from source and run on Ubuntu 24.04** in this lesson |
| **Licence** | MIT |
| **Home** | https://github.com/EricZimmerman/JLECmd · downloads: https://ericzimmerman.github.io |

#### Requirements

As LECmd. On Linux, `libolecf-utils` (`olecfinfo`, `olecfexport`) lets you look inside the compound file yourself.

#### Installation

```powershell
C:\Tools\ZimmermanTools\net9\JLECmd.exe --version    # installed by Get-ZimmermanTools
```

```bash
# Linux (validated here)
git clone -q --depth 1 https://github.com/EricZimmerman/JLECmd.git ~/tools/JLECmd-src
dotnet publish ~/tools/JLECmd-src/JLECmd/JLECmd.csproj -c Release -f net9.0 -o ~/tools/JLECmd -v quiet > /dev/null
echo 'jlecmd() { DOTNET_ROLL_FORWARD=Major ~/tools/JLECmd/JLECmd "$@"; }' >> ~/.bashrc
```

#### Configuration

From `JLECmd --help`:

| Option | Meaning |
|---|---|
| `-f FILE` / `-d DIR` | One Jump List / a folder, recursively (point it at `Recent` to get both kinds) |
| `--csv DIR --csvf NAME` | CSV output: `NAME_AutomaticDestinations.csv` and `NAME_CustomDestinations.csv` |
| `--json`/`--jsonf`, `--html`, `--pretty` | Other outputs |
| `-q` | Quiet console output |
| `--ld` / `--fd` | More / full LNK details for each entry |
| `--dumpTo DIR` | Save every embedded LNK as `AppId_<id>_DirName_<n>.lnk` (then use LECmd on them) |
| `--appIds FILE` | Add or override AppID descriptions (`appid|description` per line) |
| `--withDir` | Also show streams that the DestList doesn't reference |
| `--dt`, `--mp`, `--cp` | Timestamp format, precision, code page |

#### Verify the installation

```bash
jlecmd --version     # 2026.5.0+<commit> was used here
```

#### First use

```powershell
JLECmd.exe -d E:\Cases\WS-ALICE\tout\C\Users\alice\AppData\Roaming\Microsoft\Windows\Recent --csv E:\Cases\WS-ALICE\jumplists -q
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| `JumpList has serialized property store(s)!` on every file | JLECmd also prints this when there's simply no `DestListPropertyStore` stream. Look with `-f` before reading anything into it |
| AppID description "Unknown" | Not in the built-in list. Identify the app (its Prefetch/Amcache entries, the target types it opens) and record it with `--appIds` |
| "Created on 1582-10-15 00:00:00", no MAC | The entry has no object ID (common for network files). It means "unknown"; in the CSV the field is blank |
| Expected entries differ from actual | Entries were removed (user cleared the list) or the file is damaged. `--withDir` shows streams left in the container |
| Same file listed under two names | Jump Lists keep the path at the time of use; compare object IDs and MFT references |

---

### 🛠️ Tool 3: ShellBags Explorer (SBECmd)

| | |
|---|---|
| **What** | Eric Zimmerman's ShellBags tools: **ShellBags Explorer** (GUI tree view) and **SBECmd** (command line, CSV output). Both come in one download |
| **Why in DFIR** | Decodes the many shell item types (folders, volumes, network locations, ZIP contents, devices, Control Panel, …) from `UsrClass.dat` and `NTUSER.DAT`, rebuilds the folder tree, and shows the MRU times, the shell items' own timestamps and MFT references |
| **Platforms** | **Windows only** (closed-source .NET binaries) |
| **Licence** | Free to use; not open source |
| **Home** | https://ericzimmerman.github.io (download `ShellBagsExplorer.zip`) |

> ⚠️ **Not run here.** SBECmd is not open source, and this lab's network policy blocks Eric Zimmerman's download server, so it couldn't be built or run on Linux. Its command line below is the one used by KAPE's `SBECmd` module (KapeFiles: `Modules/EZTools/SBECmd.mkape`). The Linux labs parse the same hive with **RegRipper's `shellbags` plugin** (Day 11) and the repo's `regf_peek.py`.

#### Requirements

Windows 10/11 with the .NET 9 runtime. Collect `UsrClass.dat` **and** `NTUSER.DAT` for every user, **with** their `.LOG1`/`.LOG2` files (dirty hives, Day 11).

#### Installation (Windows)

```powershell
# Get-ZimmermanTools (Day 1) downloads ShellBagsExplorer.zip with the rest; find the two executables:
Get-ChildItem C:\Tools\ZimmermanTools -Recurse -Include SBECmd.exe, ShellBagsExplorer.exe | Select-Object FullName
```

Or download `ShellBagsExplorer.zip` from https://ericzimmerman.github.io, unblock it (`Unblock-File`) and extract it.

#### Configuration

- `SBECmd.exe -d <folder> --csv <output folder>`: process the registry hives found under `<folder>` (a KAPE collection or a folder of hives) and write CSV. This is exactly the KAPE module's command line.
- Run `SBECmd.exe --help` for the rest of the options on your version (output file name, timestamp format, transaction logs and others).
- **ShellBags Explorer**: load an offline `UsrClass.dat`/`NTUSER.DAT` from its File menu, or the live registry when run elevated on a live system.

The CSV lists each shell item with its absolute path, type, timestamps and MFT reference; check the column header on your version before writing filters.

#### Verify the installation

```powershell
SBECmd.exe --help        # prints the version and the options
```

#### First use

```powershell
SBECmd.exe -d E:\Cases\WS-ALICE\tout\C\Users\alice --csv E:\Cases\WS-ALICE\shellbags
```

Open the CSV in Timeline Explorer, or load `UsrClass.dat` in ShellBags Explorer and expand `Desktop > My Computer`, `Desktop > Network` and any removable drive.

#### Troubleshooting

| Symptom | Fix |
|---|---|
| No ShellBags for a user you know browsed folders | Look in **`UsrClass.dat`**, not only `NTUSER.DAT`. Make sure it was collected (KAPE's `RegistryHivesUser` target includes both) |
| Recent folders missing | The hive is dirty; keep the `.LOG1`/`.LOG2` files next to it |
| Every folder in a branch has the same "MRU time" | That time belongs to the most recently used child at each level only. Use each folder's own key last-write time and the other artifacts |
| Created/modified times older than the activity | They're the folder's times when the bag was **first** created, and aren't updated |
| Linux only | RegRipper's `shellbags` plugin (shown here) or Registry Explorer in a Windows VM |

---

## Part 3: Hands-on labs

First you'll read a **real** Windows 10 LNK file and a **real** Explorer Jump List (from the public test data of Eric Zimmerman's `Lnk` and `JumpList` libraries). Then you'll investigate **WS-ALICE** (Days 9–12) through alice's Recent folder, Jump Lists and ShellBags, generated by `scripts/mk_file_knowledge.py`. They continue the same story: the MFT entry numbers, names and times match the Day 10 disk, where `budget.xlsx` (MFT entry 72) was renamed `Q3-forecast.xlsx` and `notes.txt` (entry 73) was deleted at 01:02:03 on 2026-09-29. Day 9's practice drive used placeholder LNK files; these are real-format ones. (To keep the lab small, the generator writes only the shortcuts for files, not the ones Windows usually also creates for their folders.)

Run on Ubuntu 24.04 or SIFT.

```bash
sudo apt update && sudo apt install -y liblnk-utils libolecf-utils libparse-win32registry-perl git curl dotnet-sdk-10.0
git -C ~/DFIR pull 2>/dev/null || git clone https://github.com/Mr-Phoenix07/DFIR.git ~/DFIR
mkdir -p ~/cases/LAB-013/{evidence,work,notes,samples} ~/tools && cd ~/cases/LAB-013
export TZ=UTC
```

Set up RegRipper (as on Day 11) and build the two parsers (about two minutes):

```bash
[ -d ~/tools/RegRipper3.0 ] || git clone -q --depth 1 https://github.com/keydet89/RegRipper3.0.git ~/tools/RegRipper3.0
mkdir -p ~/tools/RegRipper3.0/lib/Parse/Win32Registry/WinNT
cp ~/tools/RegRipper3.0/{Base,File,Key}.pm ~/tools/RegRipper3.0/lib/Parse/Win32Registry/WinNT/
rip() { PERL5LIB=~/tools/RegRipper3.0/lib perl ~/tools/RegRipper3.0/rip.pl "$@"; }
for t in LECmd JLECmd; do
  [ -d ~/tools/$t-src ] || git clone -q --depth 1 https://github.com/EricZimmerman/$t.git ~/tools/$t-src
  git -C ~/tools/$t-src log -1 --format="$t source %h %cs"
  DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 dotnet publish ~/tools/$t-src/$t/$t.csproj -c Release -f net9.0 -o ~/tools/$t -v quiet > /dev/null
done
lecmd() { DOTNET_ROLL_FORWARD=Major ~/tools/LECmd/LECmd "$@"; }
jlecmd() { DOTNET_ROLL_FORWARD=Major ~/tools/JLECmd/JLECmd "$@"; }
lecmd --version
jlecmd --version
olecfinfo -V | head -n 1
```

```
LECmd source 8107efc 2026-05-13
JLECmd source ba276d7 2026-05-05
2026.5.0+8107efc4f9f9b4f80fd7b50ed659ffb736e29dd1
2026.5.0+ba276d761682d7abaf2d07da9aad4120b28f0938
olecfinfo 20181231
```

### Lab 1: A real Windows 10 LNK file (15 min)

```bash
cd ~/cases/LAB-013/samples
curl -sSfL -o Hello.xls.lnk "https://raw.githubusercontent.com/EricZimmerman/Lnk/master/Lnk.Test/TestFiles/Win10/Hello.xls.lnk.test"
sha256sum Hello.xls.lnk | tee ../notes/samples.sha256
xxd -l 32 Hello.xls.lnk
lecmd -f Hello.xls.lnk | sed -n '/--- Header ---/,/Property store/p' | grep -v -E '^$|Icon index|Show window|Property store|Extension block count|Block 0|End Target|Extra blocks|Target ID information|Link information ---'
```

```
cef71f7cb606efb3b4a4e6e01a7480cceac482996a846b5079f3d19e7aaedacc  Hello.xls.lnk
00000000: 4c00 0000 0114 0200 0000 0000 c000 0000  L...............
00000010: 0000 0046 8b00 0000 2000 0000 0012 762e  ...F.... .....v.
--- Header ---
  Target created:  2004-05-03 16:17:51
  Target modified: 2016-01-27 15:25:01
  Target accessed: 2005-05-12 15:40:51
  File size (bytes): 28,160
  Flags: HasTargetIdList, HasLinkInfo, HasRelativePath, IsUnicode
  File attributes: FileAttributeArchive
Relative Path: ..\..\..\..\..\Desktop\Hello.xls
Flags: VolumeIdAndLocalBasePath
>> Volume information
  Drive type: Fixed storage media (Hard drive)
  Serial number: 6A228FAA
  Label: (No label)
  Local path: C:\Users\e\Desktop\Hello.xls
  Absolute path: Hello.xls
  -File ==> Hello.xls
    Short name: Hello.xls
    Modified:    2002-06-26 18:15:36
    Long name: Hello.xls
    Created:     2004-05-03 16:17:52
    Last access: 2005-05-12 15:40:52
    MFT entry/sequence #: 151992/5 (0x251B8/0x5)
>> Tracker database block
   Machine ID:  sagerez
   MAC Address: a4:34:d9:43:f3:63
   MAC Vendor:  INTEL
   Creation:    2016-01-27 13:45:18
   Volume Droid:       38648bd4-606f-459b-91e5-d8883d4b70b1
   Volume Droid Birth: 38648bd4-606f-459b-91e5-d8883d4b70b1
   File Droid:         33d1d9f6-c4fc-11e5-b2aa-a434d943f363
   File Droid birth:   33d1d9f6-c4fc-11e5-b2aa-a434d943f363
```

Read it like an examiner:

- **Header:** `4C 00 00 00`, then the shell link CLSID (`01 14 02 00 … 46`), then the flags (`8b 00 00 00`).
- The **target** is `C:\Users\e\Desktop\Hello.xls` on a fixed disk with serial `6A228FAA`, 28,160 bytes, MFT entry 151992 sequence 5.
- **Three different "modified" times:** the header says 2016-01-27 15:25:01 (the file as of the last open), the shell item says 2002-06-26 (captured when that ID list was built, at 2-second resolution). An old creation date like 2004 usually means the file arrived with its original times (from an archive, or copied by a tool that preserves them).
- **Tracker block:** the file got its object ID on machine **`sagerez`**, network card **a4:34:d9:43:f3:63 (Intel)**, at **2016-01-27 13:45:18**. Note how the MAC address is the last part of the file droid, and the `1` that starts its third group (`11e5`) marks a version 1 GUID. The volume and birth droids are equal: the file never moved to another volume.

### Lab 2: Inside a real Jump List (15 min)

```bash
curl -sSfL -o f01b4d95cf55d32a.automaticDestinations-ms "https://raw.githubusercontent.com/EricZimmerman/JumpList/master/JumpList.Test/TestFiles/Win10/f01b4d95cf55d32a.automaticDestinations-ms"
sha256sum f01b4d95cf55d32a.automaticDestinations-ms | tee -a ../notes/samples.sha256
olecfinfo f01b4d95cf55d32a.automaticDestinations-ms | sed -n '/^Root Entry/,$p'
jlecmd -f f01b4d95cf55d32a.automaticDestinations-ms | grep -E '^Entry #|^  (Path|Pinned|Created on|Last modified|Hostname|Mac Address|Interaction count):' | head -n 24
jlecmd -f f01b4d95cf55d32a.automaticDestinations-ms --dumpTo dumped -q > /dev/null
ls dumped/f01b4d95cf55d32a.automaticDestinations-ms | sort -t_ -k4n
xxd -l 20 dumped/f01b4d95cf55d32a.automaticDestinations-ms/AppId_f01b4d95cf55d32a_DirName_7.lnk
```

```
a724713d2ff51d32e3f028c57ab906339f882de0c93dc9903f0f8b241c53fd56  f01b4d95cf55d32a.automaticDestinations-ms
Root Entry (6336 bytes)
  1 (678 bytes)
  2 (439 bytes)
  3 (439 bytes)
  4 (438 bytes)
  DestList (1812 bytes)
  5 (435 bytes)
  6 (436 bytes)
  7 (471 bytes)
  8 (389 bytes)
  9 (541 bytes)

Entry #: 7
  Path: C:\Temp
  Pinned: False
  Created on:    2015-11-24 18:39:02
  Last modified: 2015-11-24 20:31:34
  Hostname: desktop-annfp9d
  Mac Address: 00:15:5d:01:6d:02
  Interaction count: 2
Entry #: 9
  Path: C:\Temp\1
  Pinned: False
  Created on:    2015-11-24 18:39:02
  Last modified: 2015-11-24 20:31:34
  Hostname: desktop-annfp9d
  Mac Address: 00:15:5d:01:6d:02
  Interaction count: 1
Entry #: 8
  Path: C:\
  Pinned: False
  Created on:    2015-11-24 18:39:02
  Last modified: 2015-11-24 20:30:55
  Hostname: desktop-annfp9d
  Mac Address: 00:15:5d:01:6d:02
  Interaction count: 1
AppId_f01b4d95cf55d32a_DirName_1.lnk
AppId_f01b4d95cf55d32a_DirName_2.lnk
AppId_f01b4d95cf55d32a_DirName_3.lnk
AppId_f01b4d95cf55d32a_DirName_4.lnk
AppId_f01b4d95cf55d32a_DirName_5.lnk
AppId_f01b4d95cf55d32a_DirName_6.lnk
AppId_f01b4d95cf55d32a_DirName_7.lnk
AppId_f01b4d95cf55d32a_DirName_8.lnk
AppId_f01b4d95cf55d32a_DirName_9.lnk
00000000: 4c00 0000 0114 0200 0000 0000 c000 0000  L...............
00000010: 0000 0046                                ...F
```

- The container holds **nine LNK streams** (`1`–`9`) and the **`DestList`**; each dumped stream starts with the same shell link header you saw in Lab 1.
- Entries are listed in **MRU order**: entry 7 (`C:\Temp`) is the most recently used, not entry 9. The entry number is the order of *creation*.
- `00:15:5d` is a Microsoft Hyper-V MAC prefix: this test machine was a virtual machine. On a real case, a MAC address that doesn't belong to the machine you're examining means the target got its object ID **elsewhere** (a copied file or a removable drive used on another computer).

### Lab 3: alice's Recent LNK files (20 min)

```bash
cd ~/cases/LAB-013
python3 ~/DFIR/scripts/mk_file_knowledge.py evidence/WS-ALICE
(cd evidence/WS-ALICE && find . -type f -print0 | sort -z | xargs -0 sha256sum) > notes/evidence.sha256
sed -E 's/^(.{16}).{48}  \.\//\1  /' notes/evidence.sha256
R=evidence/WS-ALICE/Users/alice/AppData/Roaming/Microsoft/Windows/Recent
lecmd -d $R --csv work/lnk --csvf lnk.csv -q | grep -o 'Processed [0-9]* out of [0-9]* files'
python3 - work/lnk/lnk.csv <<'EOF'
import csv, sys
rows = list(csv.DictReader(open(sys.argv[1], encoding="utf-8-sig")))
for r in sorted(rows, key=lambda r: r["SourceModified"]):
    name = r["SourceFile"].replace("\\", "/").rsplit("/", 1)[1]
    target = r["LocalPath"] or r["NetworkPath"] + r["CommonPath"]
    if r["VolumeSerialNumber"]:
        where = f'{r["DriveType"].split(" (")[0]}, serial {r["VolumeSerialNumber"]} {r["VolumeLabel"]}'.rstrip()
    else:
        where = "network share"
    mft = r["TargetMFTEntryNumber"]
    mft = f'{int(mft, 16)}/{int(r["TargetMFTSequenceNumber"], 16)}' if mft not in ("", "0x0") else "-"
    print(f'{r["SourceModified"]}  {name}')
    print(f'    -> {target}  ({where}; MFT {mft}; {r["FileSize"]} bytes)')
    print(f'       target created {r["TargetCreated"]}, modified {r["TargetModified"]}; '
          f'tracker {r["MachineID"] or "(none)"} {r["TrackerCreatedOn"]}'.rstrip())
EOF
lnkinfo $R/upload-howto.txt.lnk | grep -E 'Drive type|Network path|Machine identifier'
```

```
  12288  Users/alice/AppData/Local/Microsoft/Windows/UsrClass.dat
    809  Users/alice/AppData/Roaming/Microsoft/Windows/Recent/Q3-forecast.xlsx.lnk
    782  Users/alice/AppData/Roaming/Microsoft/Windows/Recent/budget.xlsx.lnk
    770  Users/alice/AppData/Roaming/Microsoft/Windows/Recent/notes.txt.lnk
    928  Users/alice/AppData/Roaming/Microsoft/Windows/Recent/rc.zip.lnk
    508  Users/alice/AppData/Roaming/Microsoft/Windows/Recent/spec-01.txt.lnk
    427  Users/alice/AppData/Roaming/Microsoft/Windows/Recent/upload-howto.txt.lnk
   5120  Users/alice/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/9b9cdc69c1c24e2b.automaticDestinations-ms
   4608  Users/alice/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/b8ab77100df80ab2.automaticDestinations-ms
   6144  Users/alice/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/f01b4d95cf55d32a.automaticDestinations-ms
c5bba621f0a808b9  Users/alice/AppData/Local/Microsoft/Windows/UsrClass.dat
7934c94fc6b10339  Users/alice/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/9b9cdc69c1c24e2b.automaticDestinations-ms
4603ca2749582798  Users/alice/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/b8ab77100df80ab2.automaticDestinations-ms
6de1e3dfc0dc5f9a  Users/alice/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/f01b4d95cf55d32a.automaticDestinations-ms
5ddd04ca5f73e6fc  Users/alice/AppData/Roaming/Microsoft/Windows/Recent/Q3-forecast.xlsx.lnk
e8e247a82177f461  Users/alice/AppData/Roaming/Microsoft/Windows/Recent/budget.xlsx.lnk
54f90396d14489ac  Users/alice/AppData/Roaming/Microsoft/Windows/Recent/notes.txt.lnk
6be1fcbd1a6bc0f4  Users/alice/AppData/Roaming/Microsoft/Windows/Recent/rc.zip.lnk
7f13d2e3a83a30cb  Users/alice/AppData/Roaming/Microsoft/Windows/Recent/spec-01.txt.lnk
8375384a406aa3b9  Users/alice/AppData/Roaming/Microsoft/Windows/Recent/upload-howto.txt.lnk
Processed 6 out of 6 files
2026-09-28 10:14:31  rc.zip.lnk
    -> C:\Users\alice\AppData\Local\Temp\rc.zip  (Fixed storage media, serial 6C2F3E1A; MFT 117/1; 2048 bytes)
       target created 2026-09-28 10:13:57, modified 2026-09-28 10:13:57; tracker ws-alice 2026-09-28 10:14:31
2026-09-28 11:02:15  notes.txt.lnk
    -> C:\Users\alice\Documents\notes.txt  (Fixed storage media, serial 6C2F3E1A; MFT 73/1; 60 bytes)
       target created 2026-09-28 09:15:00, modified 2026-09-28 09:15:00; tracker ws-alice 2026-09-28 09:16:40
2026-09-28 17:48:09  budget.xlsx.lnk
    -> C:\Users\alice\Documents\budget.xlsx  (Fixed storage media, serial 6C2F3E1A; MFT 72/1; 6144 bytes)
       target created 2026-09-28 09:15:00, modified 2026-09-28 09:15:00; tracker ws-alice 2026-09-28 16:20:11
2026-09-29 01:03:44  Q3-forecast.xlsx.lnk
    -> C:\Users\alice\Documents\Q3-forecast.xlsx  (Fixed storage media, serial 6C2F3E1A; MFT 72/1; 6144 bytes)
       target created 2026-09-28 09:15:00, modified 2026-09-28 09:15:00; tracker ws-alice 2026-09-28 16:20:11
2026-09-29 01:05:31  upload-howto.txt.lnk
    -> \\203.0.113.50\drop\upload-howto.txt  (network share; MFT -; 412 bytes)
       target created 2026-09-27 22:41:09, modified 2026-09-27 22:41:09; tracker (none)
2026-09-29 01:34:12  spec-01.txt.lnk
    -> E:\finance\spec-01.txt  (Removable storage media, serial 5E1D7A2C TRANSFER; MFT 42/1; 16 bytes)
       target created 2026-09-29 01:33:21, modified 2026-09-28 09:15:00; tracker ws-alice 2026-09-29 01:34:12
	Drive type			: Not set (0)
	Network path			: \\203.0.113.50\drop\upload-howto.txt
```

(The first column of each line is the `.lnk` file's own modification time, i.e. the last time the file was opened. The generator sets it; a Linux copy can't keep the `.lnk`'s creation time.) Six LNK files, six findings:

- **`budget.xlsx` and `Q3-forecast.xlsx` are the same file.** Both point to **MFT entry 72, sequence 1**, and both trackers say the object ID was created at **2026-09-28 16:20:11**. Day 10 showed the rename at 01:02:03; the LNKs show alice used the file under its old name the day before (last at 17:48:09) and opened it under the **new name at 01:03:44**, 101 seconds after the rename.
- **`notes.txt` no longer exists** (Day 10: deleted at 01:02:03), but its LNK keeps the path, size (60 bytes) and **MFT 73/1**. Day 10's `svchost.exe` is MFT **73/2**: the same record, reused. The LNK is your only proof of what entry 73 used to be, short of carving.
- **`upload-howto.txt` was opened from the share `\\203.0.113.50\drop`** at 01:05:31, 36 seconds after that path was typed into Explorer (Day 11: TypedPaths at 01:04:55). There's no volume serial and **no tracker block**: the remote server didn't supply an object ID. `lnkinfo` (liblnk, a separate parser) agrees.
- **`spec-01.txt` was opened from `E:\finance` on a removable volume labelled `TRANSFER`, serial `5E1D7A2C`**, at 01:34:12. Its target was **created at 01:33:21** but **modified 2026-09-28 09:15:00**: a copy keeps the modification time and gets a new creation time. Someone copied alice's project file to a USB drive at about 01:33 and checked it opened. That's a **new exfiltration channel** that Days 9–12 didn't show, and plugging in a USB drive suggests someone was **physically at** WS-ALICE.
- **`rc.zip`** (from Day 9's download) was opened through the shell on 2026-09-28 at 10:14:31, about half a minute after it was written.
- All local targets got their object IDs on **`ws-alice`**: the tracker's MAC address belongs to this machine (check it against the network adapter in the SYSTEM hive or DHCP logs on a real case).

### Lab 4: Jump Lists, per application (15 min)

```bash
jlecmd -d $R --csv work/jl --csvf jl.csv -q | grep -o 'Processed [0-9]* out of [0-9]* files'
python3 - work/jl/jl_AutomaticDestinations.csv <<'EOF'
import csv, sys
rows = list(csv.DictReader(open(sys.argv[1], encoding="utf-8-sig")))
app = None
for r in sorted(rows, key=lambda r: (r["AppId"], int(r["MRU"]))):
    if r["AppId"] != app:
        app = r["AppId"]
        print(f'{app}  {r["AppIdDescription"]}')
    pin = "  PINNED" if r["PinStatus"] == "True" else ""
    print(f'  MRU {r["MRU"]}  last used {r["LastModified"]}  x{r["InteractionCount"]:<2} {r["Path"]}{pin}')
    print(f'         object ID created {r["CreationTime"] or "(no object ID)":19}  {r["FileDroid"]}')
EOF
```

```
Processed 3 out of 3 files
9b9cdc69c1c24e2b  Notepad 64-bit
  MRU 0  last used 2026-09-29 01:34:12  x1  E:\finance\spec-01.txt
         object ID created 2026-09-29 01:34:12  dfb3b556-bba5-11f1-9a2a-e4f89c5a217d
  MRU 1  last used 2026-09-29 01:05:31  x1  \\203.0.113.50\drop\upload-howto.txt
         object ID created (no object ID)       
  MRU 2  last used 2026-09-28 11:02:15  x3  C:\Users\alice\Documents\notes.txt
         object ID created 2026-09-28 09:16:40  508eaf67-bb1d-11f1-9a2a-e4f89c5a217d
b8ab77100df80ab2  Microsoft Office Excel x64
  MRU 0  last used 2026-09-29 01:03:44  x1  C:\Users\alice\Documents\Q3-forecast.xlsx
         object ID created 2026-09-28 16:20:11  7a84f48d-bb58-11f1-9a2a-e4f89c5a217d
  MRU 1  last used 2026-09-28 17:48:09  x4  C:\Users\alice\Documents\budget.xlsx
         object ID created 2026-09-28 16:20:11  7a84f48d-bb58-11f1-9a2a-e4f89c5a217d
f01b4d95cf55d32a  Windows Explorer Windows 8.1
  MRU 0  last used 2026-09-29 01:33:41  x1  E:\finance
         object ID created 2026-09-29 01:33:41  cd9cfe66-bba5-11f1-9a2a-e4f89c5a217d
  MRU 1  last used 2026-09-29 01:05:02  x1  \\203.0.113.50\drop
         object ID created (no object ID)       
  MRU 2  last used 2026-09-29 01:04:58  x1  C:\Users\alice\AppData\Local\Temp\rc
         object ID created 2026-09-29 01:04:58  ca571bfb-bba1-11f1-9a2a-e4f89c5a217d
  MRU 3  last used 2026-09-28 16:19:52  x12 C:\Users\alice\Documents  PINNED
         object ID created 2026-03-02 09:41:07  eff78463-161b-11f1-9a2a-e4f89c5a217d
```

What the Jump Lists add:

- **Which program.** `upload-howto.txt` and `spec-01.txt` were read in **Notepad**; the spreadsheet in **Excel**. The Explorer list shows the folders: **Temp\rc**, the **share**, and **`E:\finance`** on the USB drive.
- **How often.** alice opened `budget.xlsx` **four times** on 2026-09-28 (normal work) and `notes.txt` three times. Everything in the night window was opened **once**.
- **The rename again.** Excel's two entries have the **same object ID** (`7a84f48d-…`): one file, two names. Jump Lists aren't updated by renames.
- **Pinned `Documents`** with 12 interactions since 2026-03-02 is alice's normal habit; it gives you a baseline.
- The network entries have **no object ID** (blank in the CSV; `jlecmd -f` prints `1582-10-15 00:00:00`).

### Lab 5: ShellBags, the folders alice browsed (15 min)

```bash
U=evidence/WS-ALICE/Users/alice/AppData/Local/Microsoft/Windows/UsrClass.dat
rip -r $U -p shellbags 2>/dev/null | tail -n +6 | awk -F'|' '{printf "%-20s|%-21s|%-13s|%s\n", $1, $4, $6, $7}'
python3 ~/DFIR/scripts/regf_peek.py $U --tree | grep -E '^2026.*BagMRU' | sed 's/ S-1-5-21-[-0-9]*_Classes.*Shell.BagMRU/  BagMRU/'
python3 ~/DFIR/scripts/regf_peek.py $U --tree | grep -A1 -E 'BagMRU.0.1$' | tail -n 1
```

```
2026-09-29 01:33:41  |                      |              |My Computer [Desktop\0\]
                     |                      |              |My Computer\C:\ [Desktop\0\0\]
2026-09-29 01:04:58  | 2026-09-28 09:15:00  | 64/1         |My Computer\C:\Users [Desktop\0\0\0\]
2026-09-29 01:04:58  | 2026-09-28 09:15:00  | 65/1         |My Computer\C:\Users\alice [Desktop\0\0\0\0\]
                     | 2026-09-28 09:15:00  | 66/1         |My Computer\C:\Users\alice\Documents [Desktop\0\0\0\0\0\]
2026-09-29 01:04:58  | 2026-09-28 09:15:00  | 69/1         |My Computer\C:\Users\alice\AppData [Desktop\0\0\0\0\1\]
2026-09-29 01:04:58  | 2026-09-28 09:15:00  | 70/1         |My Computer\C:\Users\alice\AppData\Local [Desktop\0\0\0\0\1\0\]
2026-09-29 01:04:58  | 2026-09-28 09:15:00  | 71/1         |My Computer\C:\Users\alice\AppData\Local\Temp [Desktop\0\0\0\0\1\0\0\]
2026-09-29 01:04:58  | 2026-09-28 10:14:22  | 118/1        |My Computer\C:\Users\alice\AppData\Local\Temp\rc [Desktop\0\0\0\0\1\0\0\0\]
2026-09-29 01:33:41  |                      |              |My Computer\E:\ [Desktop\0\1\]
2026-09-29 01:33:41  | 2026-09-29 01:33:20  | 41/1         |My Computer\E:\finance [Desktop\0\1\0\]
                     |                      |              |My Network Places [Desktop\1\]
2026-09-29 01:05:02  |                      |              |My Network Places\\\203.0.113.50 [Desktop\1\0\]
2026-09-29 01:05:02  |                      |              |My Network Places\\\203.0.113.50\\\203.0.113.50\drop [Desktop\1\0\0\]
2026-09-29 01:33:41.8812006   BagMRU
2026-09-29 01:33:41.8812006   BagMRU\0
2026-09-29 01:04:58.4031227   BagMRU\0\0
2026-09-29 01:04:58.4031227   BagMRU\0\0\0
2026-09-29 01:04:58.4031227   BagMRU\0\0\0\0
2026-09-28 16:19:52.6610045   BagMRU\0\0\0\0\0
2026-09-29 01:04:58.4031227   BagMRU\0\0\0\0\1
2026-09-29 01:04:58.4031227   BagMRU\0\0\0\0\1\0
2026-09-29 01:04:58.4031227   BagMRU\0\0\0\0\1\0\0
2026-09-29 01:04:58.4031227   BagMRU\0\0\0\0\1\0\0\0
2026-09-29 01:33:41.8812006   BagMRU\0\1
2026-09-29 01:33:41.8812006   BagMRU\0\1\0
2026-09-29 01:05:02.9120338   BagMRU\1
2026-09-29 01:05:02.9120338   BagMRU\1\0
2026-09-29 01:05:02.9120338   BagMRU\1\0\0
                               0 [REG_BINARY] = 56 00 31 00 00 00 00 00 3d 5d 2a 0c 10 00 66 69 6e 61 6e 63 65 00 40 00 ...
```

The columns are: MRU time | the folder's created time (from its shell item) | MFT entry/sequence | path [key path].

- **Three places browsed in the night window:** `C:\Users\alice\AppData\Local\Temp\rc` (01:04:58), the share **`\\203.0.113.50\drop`** (01:05:02) and **`E:\finance`** on the USB drive (01:33:41). The USB drive is unplugged by now; the ShellBag remains.
- **Read MRU times with care.** RegRipper puts each key's last-write time on the child that is first in that key's `MRUListEx`. `Documents` has no MRU time (its sibling `AppData` was used more recently), but its own key `BagMRU\0\0\0\0\0` was last written **2026-09-28 16:19:52**, matching the Explorer Jump List. `My Computer\C:\` has none because `E:\` was browsed after it.
- **The shell item's times are the folder's own**, captured when the bag was created: `E:\finance` was **created 01:33:20** on the USB drive (MFT 41/1, so the drive is **NTFS**), `Temp\rc` at 10:14:22 the day before (when `rc.zip` was extracted).
- The last line is the raw shell item for `finance`: size `0x56`, type `0x31` (folder), a zero file size, the FAT modified time, attributes `0x10` (directory), then the name. The same bytes appear in the LNK target ID lists.
- RegRipper prints the share as `\\\203.0.113.50\\\203.0.113.50\drop` because the share's shell item holds the full UNC path. ShellBags Explorer displays the same tree more readably.

### Lab 6: One file-and-folder timeline (10 min)

Merge the LNK files, Jump Lists and ShellBags (for ShellBags keep only the deepest folder at each MRU time):

```bash
python3 - <<'EOF'
import csv, re, subprocess
ev = []
for r in csv.DictReader(open("work/lnk/lnk.csv", encoding="utf-8-sig")):
    target = r["LocalPath"] or r["NetworkPath"] + r["CommonPath"]
    ev.append((r["SourceModified"], "LNK", f"opened {target}"))
for r in csv.DictReader(open("work/jl/jl_AutomaticDestinations.csv", encoding="utf-8-sig")):
    app = next(a for a in ("Excel", "Notepad", "Explorer") if a in r["AppIdDescription"])
    ev.append((r["LastModified"], "JumpList", f'{app} used {r["Path"]} (x{r["InteractionCount"]})'))
out = subprocess.run(["bash", "-c", "PERL5LIB=~/tools/RegRipper3.0/lib perl ~/tools/RegRipper3.0/rip.pl "
                      "-r evidence/WS-ALICE/Users/alice/AppData/Local/Microsoft/Windows/UsrClass.dat -p shellbags 2>/dev/null"],
                     capture_output=True, text=True).stdout
bags = []
for line in out.splitlines():
    f = [x.strip() for x in line.split("|")]
    if len(f) == 7 and re.match(r"\d{4}-", f[0]):
        bags.append((f[0], f[6].split(" [")[0]))
for t, path in bags:
    if not any(u == t and p != path and p.startswith(path.rstrip("\\") + "\\") for u, p in bags):
        if "\\\\" in path:
            path = "\\\\" + path.rsplit("\\\\", 1)[1]
        ev.append((t, "ShellBag", "browsed " + path.replace("My Computer\\", "")))
for t, src, what in sorted(ev):
    print(f"{t}  {src:<8}  {what}")
EOF
```

```
2026-09-28 10:14:31  LNK       opened C:\Users\alice\AppData\Local\Temp\rc.zip
2026-09-28 11:02:15  JumpList  Notepad used C:\Users\alice\Documents\notes.txt (x3)
2026-09-28 11:02:15  LNK       opened C:\Users\alice\Documents\notes.txt
2026-09-28 16:19:52  JumpList  Explorer used C:\Users\alice\Documents (x12)
2026-09-28 17:48:09  JumpList  Excel used C:\Users\alice\Documents\budget.xlsx (x4)
2026-09-28 17:48:09  LNK       opened C:\Users\alice\Documents\budget.xlsx
2026-09-29 01:03:44  JumpList  Excel used C:\Users\alice\Documents\Q3-forecast.xlsx (x1)
2026-09-29 01:03:44  LNK       opened C:\Users\alice\Documents\Q3-forecast.xlsx
2026-09-29 01:04:58  JumpList  Explorer used C:\Users\alice\AppData\Local\Temp\rc (x1)
2026-09-29 01:04:58  ShellBag  browsed C:\Users\alice\AppData\Local\Temp\rc
2026-09-29 01:05:02  JumpList  Explorer used \\203.0.113.50\drop (x1)
2026-09-29 01:05:02  ShellBag  browsed \\203.0.113.50\drop
2026-09-29 01:05:31  JumpList  Notepad used \\203.0.113.50\drop\upload-howto.txt (x1)
2026-09-29 01:05:31  LNK       opened \\203.0.113.50\drop\upload-howto.txt
2026-09-29 01:33:41  JumpList  Explorer used E:\finance (x1)
2026-09-29 01:33:41  ShellBag  browsed E:\finance
2026-09-29 01:34:12  JumpList  Notepad used E:\finance\spec-01.txt (x1)
2026-09-29 01:34:12  LNK       opened E:\finance\spec-01.txt
```

Combined with Days 10–12, the night now reads: **01:02:03** files renamed and deleted (Day 10) → **01:03:44** the renamed spreadsheet opened in Excel → **01:04:55–01:05:02** `Temp\rc` and the share `\\203.0.113.50\drop` typed and browsed (Days 11 and 13) → **01:05:13** PsExec service runs (Day 12) → **01:05:31** `upload-howto.txt` read from the share → **01:12:47** rclone's first run (Day 12) → **01:33:20–01:34:12** project files copied to a USB drive `TRANSFER` (serial `5E1D7A2C`) and checked. For each event, the LNK file, the Jump List and the ShellBag agree to the second. Record the USB serial number in your notes: the event logs (Day 14) and the registry's device history are where you'll look for the device itself.

---

## ✅ Knowledge check

1. What do LNK files, Jump Lists and ShellBags each prove, and which of them can show the **application** that opened a file?
2. An LNK's header says the target was modified 2016-01-27, but the shell item in its target ID list says 2002-06-26. Which is right?
3. Two Recent LNKs point to different file names but have the same MFT entry and sequence number and the same file droid. What happened?
4. Which fields of an LNK tell you the target was on a USB drive, and which value would you use to match it to a seized drive?
5. What does the MAC address in a tracker block or DestList entry tell you, and why could it differ from the examined machine's own network card?
6. JLECmd shows `Created on: 1582-10-15 00:00:00` for an entry. What does that mean?
7. In a ShellBags report, `Documents` has no MRU time while its sibling `AppData` has 01:04:58. How do you find when `Documents` was last browsed?
8. A ShellBag entry exists for `E:\finance`, but the folder isn't on any drive you have. What can you still say about it?
9. A suspicious `invoice.pdf.lnk` arrives in a ZIP file. Which three parts of it would you examine first?

<details>
<summary><b>Answers</b></summary>

1. **LNK files**: a specific file (or folder) was opened through the shell, with its path, volume, size and times. **Jump Lists**: which **application** opened which files or folders, when last, how often and whether pinned. **ShellBags**: which **folders** were displayed in Explorer or a file dialog, including removable and network locations. Jump Lists show the application.
2. Both, for different moments. The **header** holds the target's times as of the **last open** (updated each time the LNK is written). The **shell item** times were captured when that ID list was built, at 2-second resolution. Use the header for "as of the last open", and treat differences as information (the file changed in between).
3. It's **the same file**, renamed (or moved within the volume). The MFT entry/sequence and the object ID stay with the file; the LNKs and Jump List entries keep the name it had when opened.
4. In **LinkInfo**: the **drive type** `Removable`, the **volume serial number** and the **volume label** (and the local path's drive letter). Match the **serial number**: it's written when the volume is formatted, so the seized drive will show the same value (unless reformatted). The drive letter and label can change.
5. It's the network card of the machine that **created the object ID** (from the version 1 GUID), usually where the file was first linked. A different MAC means the object ID was created on **another computer**: the file came from elsewhere (copied with its object ID, on a removable NTFS drive used on another machine, or an LNK built on an attacker's machine).
6. The entry has **no object ID** (all zeros): `1582-10-15` is the zero point of version 1 GUID time. It means "unknown", not a date. It's common for files on network shares.
7. Use the **last-write time of `Documents`' own BagMRU key** (and its subkeys), and confirm with the Explorer Jump List or LNK files. The MRU time in the report is only valid for the first child in the parent's `MRUListEx`.
8. That the user **browsed** it in Explorer, the **drive letter** at the time, the folder's **created/modified/accessed times** when the bag was created and, if the drive was NTFS, its **MFT entry and sequence**. It doesn't tell you which files were in it or opened: look for LNKs and Jump List entries with that path and the volume serial.
9. The **target and arguments** (what actually runs: often `cmd.exe` or `powershell.exe` with a long command line), the **icon location** (disguise) and the **tracker block / volume serial / machine ID** (traces of the attacker's build machine, useful for linking samples).

</details>

---

## 📚 Further reading

- Microsoft, *[MS-SHLLINK]: Shell Link (.LNK) Binary File Format* (https://learn.microsoft.com/openspecs/windows_protocols/ms-shllink/)
- libyal documentation: *Windows Shortcut File (LNK) format* (liblnk), *Windows Shell Item format* (libfwsi) and *OLE Compound File format* (libolecf), on GitHub under `libyal/*/documentation`
- Eric Zimmerman's `Lnk`, `JumpList` and `ExtensionBlocks` libraries (GitHub): the parsing code behind LECmd and JLECmd, with test files used today
- SANS *Windows Forensic Analysis* poster, "File/Folder Opening" section
- 13Cubed, *LNK Files*, *Jump Lists* and *ShellBags* videos (YouTube)

---

## ⏭️ Tomorrow: Day 14

**Windows Event Logs: EVTX structure and key event IDs.** Tools: **EvtxECmd**, **evtx_dump**, **FullEventLogView**.
You'll look inside the EVTX format and learn the event IDs that matter for logons, services, scheduled tasks, PowerShell and USB devices.

---

<sub>Part of the <a href="../README.md">DFIR Daily</a> series · <a href="../CURRICULUM.md">Full 60-day curriculum</a> · For educational and authorised use only.</sub>
