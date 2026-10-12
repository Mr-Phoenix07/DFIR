# Day 15: Event-Log Threat Hunting with Sigma Rules

> **Phase 2: Windows Forensics** · **Level:** 🟡 Intermediate · **Time:** ~4 hours (reading + labs) · **Posted:** 2026-10-12
>
> **Tools today:** 🛠️ Hayabusa · 🛠️ Chainsaw · 🛠️ DeepBlueCLI

---

## 🎯 Learning objectives

By the end of today you will be able to:

1. Explain what **Sigma** is, read a Sigma rule (logsource, detection, condition, level, ATT&CK tags) and say which events it can match.
2. Explain why **field mapping** decides whether a rule written for Sysmon also works on Security 4688 events, and recognise the gap in practice.
3. Sweep a folder of event logs with **Hayabusa** and **Chainsaw**, read their output, and know what **DeepBlueCLI** checks and when to use it.
4. Treat alerts as **leads**: recognise noise, misattribution and **false negatives** (thresholds, missing logging, rule variants).
5. Write and test your own **Sigma rule** and a **correlation rule**, and check them for false positives.

---

## Part 1: The lesson

Yesterday you read events one at a time. That works for a single workstation and a known time window. It doesn't work for 500 machines and three months of logs, or when you don't yet know what you're looking for. **Threat hunting with detection rules** turns the question around: run hundreds of known-bad patterns over everything, and let the matches point you to where to look first.

### 1.1 Sigma: one rule format for many tools

**Sigma** is an open, vendor-neutral format for describing suspicious log events in YAML. A rule written once can be used by SIEMs (after conversion), by forensic tools such as Hayabusa and Chainsaw, and shared between teams. The community repository **SigmaHQ/sigma** holds more than 3,000 rules; Windows event logs are the biggest part.

```yaml
title: PsExec Service Installation                  # what it detects
id: 42c575ea-e41e-41f1-b248-8093c3e82a28           # a unique, permanent UUID
status: test                                        # stable / test / experimental / deprecated / unsupported
tags: [attack.execution, attack.t1569.002]          # MITRE ATT&CK technique(s)
logsource:                                          # WHICH logs the rule is about
    product: windows
    service: system                                 #   -> the System log
detection:
    selection_eid:                                  # a map = all fields must match (AND)
        Provider_Name: 'Service Control Manager'
        EventID: 7045
    selection_service:                              # a list = any item may match (OR)
        - ServiceName: 'PSEXESVC'
        - ImagePath|endswith: '\PSEXESVC.exe'       # field|modifier: value
    condition: all of selection_*                   # how the named selections combine
falsepositives: [Unknown]
level: medium                                       # informational / low / medium / high / critical
```

| Part | What to know |
|---|---|
| `logsource` | `product` + `service` (a specific log: `security`, `system`, `sysmon`…) or `category` (a kind of event: `process_creation`, `ps_script`, `network_connection`…). The **tool** decides which channels and event IDs that means |
| `detection` | Named selections. Field **modifiers**: `contains`, `startswith`, `endswith`, `all`, `re` (regular expression), `base64offset`, `cidr`, `windash`… Values are case-insensitive unless stated |
| `condition` | Boolean logic over selections: `selection and not filter`, `1 of selection_*`, `all of them` |
| `level` | Severity guide for triage, not a verdict |
| Correlation rules | A newer part of the specification: `event_count`, `value_count` and `temporal` rules count or combine other rules' matches over a **timespan** (brute force, spraying, sequences) |

**The hard part: `category: process_creation`.** Most Sigma process rules are written with **Sysmon** field names (`Image`, `ParentImage`, `CommandLine`, `OriginalFileName`). The same activity in the **Security** log (4688) uses different names (`NewProcessName`, `ParentProcessName`) and lacks some fields entirely (no `OriginalFileName`, no hashes). A tool must **map** fields per log source, or the rule silently matches nothing. You'll see this decide the outcome in Lab 4.

### 1.2 The three tools

| | **Hayabusa** | **Chainsaw** | **DeepBlueCLI** |
|---|---|---|---|
| From | Yamato Security (Japan) | WithSecure Labs | Eric Conrad / SANS |
| Language | Rust (Windows, Linux, macOS) | Rust (Windows, Linux, macOS) | PowerShell (Windows) |
| Rules | **hayabusa-rules**: SigmaHQ rules **converted** per log source (a copy for Sysmon and a copy for built-in logs, with `Channel`/`EventID` and field names filled in), plus ~200 Hayabusa rules for logons, services, log clearing… | **SigmaHQ rules as-is** + a **mapping file** that tells Chainsaw which event fields Sigma names refer to, plus ~130 Chainsaw rules | Fixed logic in the script: regexes, thresholds, an obfuscation score. No Sigma |
| Output | One timeline (CSV/JSON/JSONL) of alerts with levels and details (ATT&CK tags in the verbose profiles); results summary; HTML report | Tables, CSV per rule group, JSON/JSONL | PowerShell objects (pipe to CSV/JSON/HTML) |
| Extras | `logon-summary`, `eid-metrics`, `search`, `pivot-keywords-list`, `extract-base64`, correlation rules, live analysis | `search` (keywords, regex, Tau expressions), `analyse gaps` (deleted-record detection), shimcache and SRUM analysis | Base64/compressed command decoding, Sysmon hash safelisting (DeepBlueHash) |
| Status | Active (v4.1.0, September 2026) | Active (v2.16.5, August 2026) | Last updated June 2023 (still usable) |

### 1.3 Reading results like an analyst

- **An alert is a lead, not a finding.** Confirm it in the raw event (Day 14) and with other artifacts (Days 10–13).
- **Volume isn't severity.** One attacker can produce thousands of identical "high" alerts (Lab 2), and one quiet "low" can be the key event. Group by rule and host before reading.
- **False positives:** admin tools, software deployment and backup agents look like attackers. Rules list typical `falsepositives`; tune with exclusions, level tuning and noisy-rule lists.
- **False negatives** are the dangerous ones: the log wasn't enabled (4688, 4104, Sysmon), the tool can't map the fields, the attacker used a **variant** the rule doesn't cover, or the activity stayed **below a threshold**. Lab 4 shows the last three on WS-ALICE, and Lab 5 fixes two of them.
- **Mislabels:** a rule fires for the right reason with the wrong story. DeepBlueCLI calls Sysinternals PsExec's `%SystemRoot%\PSEXESVC.exe` a "Metasploit-style" path (Part 2). Read *why* it fired.
- **Write case rules.** Once you know an indicator (a file name, a share, a script pattern), turn it into a rule and sweep every other machine: that's how one compromised host becomes a scoped incident.

---

## Part 2: Tools

---

### 🛠️ Tool 1: Hayabusa

| | |
|---|---|
| **What** | A Windows event log **fast forensics timeline generator and threat-hunting tool** by Yamato Security |
| **Why in DFIR** | Turns one host's or thousands of hosts' `.evtx` files into a single, levelled alert timeline (CSV/JSON/JSONL) for Timeline Explorer, Elastic or Timesketch; built-in logon summaries and event metrics; Sigma correlation rules; GeoIP; can run live on a host or from Velociraptor |
| **Platforms** | Windows, Linux, macOS (release binaries or build from source). **Built from v4.1.0 and run on Ubuntu 24.04** in this lesson |
| **Licence** | GNU AGPLv3 (tool); rules under the Detection Rule License (DRL) 1.1 |
| **Home** | https://github.com/Yamato-Security/hayabusa · docs: https://yamato-security.github.io/hayabusa/ · rules: https://github.com/Yamato-Security/hayabusa-rules |

#### Requirements

The release packages need nothing else. To build: **Rust 1.97.1 or newer** for v4.1.0 (the `rust-version` in its `Cargo.toml`), plus `libssl-dev` and `perl` on Linux (the project's compiling notes). The **rules** live in a separate repository and go in `./rules` (or `-r`/`-c`).

#### Installation

```powershell
# Windows: download the release for your platform from
#   https://github.com/Yamato-Security/hayabusa/releases   (VER = e.g. 4.1.0)
# extract it, then fetch the latest rules into .\rules:
.\hayabusa-VER-win-x64.exe update-rules
```

(The executable is named per version and platform, e.g. `hayabusa-x.x.x-win-x64.exe`. For running on a suspect endpoint, the project also ships **live-response** packages: the binary plus the rules XOR-encoded in a single file, so antivirus doesn't trip over thousands of `.yml` files and fewer files are written to the disk.)

```bash
# Linux/macOS: build a release tag from source (validated here)
sudo apt install -y git libssl-dev perl
rustup update stable                                     # v4.1.0 needs Rust 1.97.1+
git clone --depth 1 --branch v4.1.0 https://github.com/Yamato-Security/hayabusa.git ~/tools/hayabusa-src
cd ~/tools/hayabusa-src && cargo build --release         # binary: target/release/hayabusa
git clone --depth 1 https://github.com/Yamato-Security/hayabusa-rules.git ~/tools/hayabusa-rules
```

The project warns that its `main` branch is for development: build from a **release tag**. `hayabusa update-rules` replaces files in `rules/` (keep copies of anything you edit; new files you add are kept).

#### Configuration

From `hayabusa help dfir-timeline` and the command reference:

| Option | Meaning |
|---|---|
| `dfir-timeline -d DIR` / `-f FILE` / `-l` | Scan a folder of logs / one file / the live `winevt\Logs` folder |
| `-o FILE`, `-t csv\|json\|jsonl`, `-C` | Output file, format, overwrite |
| `-r DIR`, `-c DIR` | Rules directory (default `./rules`), rules config directory (default `./rules/config`) |
| `-w` | No scan wizard (otherwise it asks which rule sets to enable) |
| `-m LEVEL` / `-e LEVEL` | Minimum / exact rule level (`informational`, `low`, `medium`, `high`, `critical`) |
| `-p PROFILE` | Output columns (`hayabusa list-profiles`); e.g. `verbose`, `super-verbose`, `timesketch-verbose` |
| `-U`, `-s` | Timestamps in UTC (default: local time); sort the timeline |
| `-H FILE` | HTML results report |
| `-n`, `-D`, `-u` | Also enable noisy, deprecated, unsupported rules |
| `--timeline-start`, `--timeline-end`, `--include-eid`, `--exclude-computer` … | Narrow the scan |
| `-q`, `-K`, `-N` | No banner, no colour, no results summary |

Rule behaviour is tuned in `rules/config/` (`level_tuning.txt` with the `level-tuning` command, `noisy_rules.txt`, `exclude_rules.txt`, `default_details.txt` for the *Details* column). Other commands: `logon-summary`, `eid-metrics`, `computer-metrics`, `log-metrics`, `search`, `pivot-keywords-list`, `extract-base64`, `sort-csv`.

#### Verify the installation

```bash
~/tools/hayabusa-src/target/release/hayabusa help | head -n 3     # "Hayabusa v4.1.0 - Suzumushi Release"
```

#### First use

```bash
hayabusa dfir-timeline -d /cases/WS-ALICE/winevt/Logs -r ~/tools/hayabusa-rules -c ~/tools/hayabusa-rules/config \
         -w -U -s -m low -o ws-alice-hayabusa.csv
hayabusa logon-summary -d /cases/WS-ALICE/winevt/Logs -c ~/tools/hayabusa-rules/config -U
```

Open the CSV in Timeline Explorer: sort by *Level*, then filter by *RuleTitle* and *Computer*.

#### Troubleshooting

| Symptom | Fix |
|---|---|
| `package requires rustc 1.97.1` when building | `rustup update stable`, or download a release binary |
| It stops and asks questions | That's the scan wizard: add `-w` for scripted runs |
| Times don't match other tools | Hayabusa prints **local time** by default; use `-U` (UTC) |
| Thousands of identical alerts | Group by *RuleTitle*; use `-m medium`, add the rule to `exclude_rules.txt`, or tune its level. Don't delete the evidence: note the noise |
| Expected detection missing | Rule not loaded (level filters, noisy/deprecated lists), log not scanned (channel filter: try `-a`/`-A`), or the event simply isn't logged on that system |
| Rows in a different order between runs | Use `-s` to sort before comparing outputs |

---

### 🛠️ Tool 2: Chainsaw

| | |
|---|---|
| **What** | WithSecure Labs' tool for rapidly searching and hunting through Windows forensic artefacts |
| **Why in DFIR** | Runs **SigmaHQ rules directly** (through a mapping file) plus its own rules over event logs (and MFT records); fast keyword/regex/field **search**; **gap analysis** for deleted records; shimcache and SRUM analysis; table, CSV, JSON or JSONL output |
| **Platforms** | Windows, Linux, macOS (release binaries or build from source). **Built from v2.16.5 and run on Ubuntu 24.04** in this lesson |
| **Licence** | GNU GPLv3 |
| **Home** | https://github.com/WithSecureLabs/chainsaw · releases: https://github.com/WithSecureLabs/chainsaw/releases |

#### Requirements

The binary, its `mappings/` and `rules/` folders (from the repository or the release package) and a copy of the **Sigma** rules. Building needs a recent Rust (edition 2024).

#### Installation

```bash
# Linux/macOS: build a release tag (validated here)
git clone --depth 1 --branch v2.16.5 https://github.com/WithSecureLabs/chainsaw.git ~/tools/chainsaw-src
cd ~/tools/chainsaw-src && cargo build --release          # binary: target/release/chainsaw
git clone --depth 1 --branch r2026-07-01 https://github.com/SigmaHQ/sigma.git ~/tools/sigma   # a dated Sigma release
```

```powershell
# Windows: download the release archive for your platform (VER = e.g. 2.16.5) from
#   https://github.com/WithSecureLabs/chainsaw/releases
# keep its mappings\ and rules\ folders next to chainsaw.exe, and clone or download SigmaHQ/sigma
.\chainsaw.exe --version
```

#### Configuration

From `chainsaw --help` and `chainsaw hunt --help`:

| Option | Meaning |
|---|---|
| `hunt PATH… -s SIGMA --mapping MAP [-r RULES]` | Hunt with Sigma rules (mapped with `mappings/sigma-event-logs-all.yml`) and Chainsaw's own rules |
| `--level`, `--status`, `--kind` | Only rules of these levels / statuses / kinds |
| `--from`, `--to` | Time window (`YYYY-MM-ddTHH:mm:SS`) |
| `--csv` / `--json` / `--jsonl` / `--log`, `-o PATH` | Output format; with `--csv`, `-o` is a folder with one CSV per rule group |
| `--timezone TZ` / `--local` | Output time zone (default UTC) |
| `--full`, `--metadata`, `--column-width` | Table output detail |
| `search PATTERN PATH` / `-e REGEX` / `-t 'Event.System.EventID: =4104'` | Keyword, regex and Tau-expression search (`-i` ignore case, `--match-any`) |
| `analyse gaps PATH` | RecordID and time gaps (default ≥ 30 min) that may mean deleted records |
| `lint PATH --kind sigma` | Check that rules load |
| `--no-banner` | Global option: goes **before** the subcommand |

The **mapping file** is the heart of Sigma support: it tells Chainsaw which logs each `logsource` means (e.g. `process_creation` = Sysmon 1 and Security 4688) and where each Sigma field lives in the event (`Image` → `Event.EventData.Image`). It also excludes rules known not to work.

#### Verify the installation

```bash
~/tools/chainsaw-src/target/release/chainsaw --version     # chainsaw 2.16.5
```

#### First use

```bash
chainsaw hunt /cases/WS-ALICE/winevt/Logs -s ~/tools/sigma/rules --mapping ~/tools/chainsaw-src/mappings/sigma-event-logs-all.yml \
         -r ~/tools/chainsaw-src/rules --csv -o ws-alice-chainsaw
chainsaw search -i rclone /cases/WS-ALICE/winevt/Logs
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| "Loading forensic artefacts from: …/sigma/rules" and only Chainsaw rules loaded | The first positional argument is a **rules** path unless you use `-s`/`-r`. Put the log path first and Sigma behind `-s` |
| `unexpected argument '--no-banner'` | It's a global option: `chainsaw --no-banner hunt …` |
| `Loaded … detection rules (N not loaded)` | Some Sigma rules use features or log sources the mapping doesn't support. Normal; check with `lint` if a rule you need is missing |
| Process rules never fire on Security 4688 | The mapping passes Sysmon names (`Image`, `ParentImage`) through unchanged, and 4688 has `NewProcessName` instead. Rules that only use `CommandLine` can still match. Use Sysmon logs, Hayabusa, or extend the mapping (Lab 4) |
| Correlation rules don't work | Chainsaw 2.16.5 doesn't implement Sigma correlations; its own rules can count with an `aggregate` section instead (e.g. "Account Brute Force": more than 5 failed logons for one user) |

---

### 🛠️ Tool 3: DeepBlueCLI

| | |
|---|---|
| **What** | A PowerShell module for threat hunting in Windows event logs by Eric Conrad (SANS) |
| **Why in DFIR** | Quick, dependency-free triage on any Windows machine: new users and admin group changes, password guessing and spraying, suspicious services, event log clearing and service tampering, long, obfuscated or Base64-encoded command lines (it decodes them), PowerShell download cradles, Mimikatz, EMET/AppLocker blocks |
| **Platforms** | **Windows** (PowerShell; it reads logs with `Get-WinEvent`). The included `DeepBlue.py` is an old Python 2 "alpha" port (command-line checks only) |
| **Licence** | GNU GPLv3 |
| **Home** | https://github.com/sans-blue-team/DeepBlueCLI (last updated June 2023; still works, but no new detections) |

> ⚠️ **Not run here.** `Get-WinEvent` doesn't exist in PowerShell on Linux, and `DeepBlue.py` needs Python 2, which Ubuntu 24.04 doesn't ship. Everything below comes from its README and `DeepBlue.ps1`. Its **sample logs** (real attacks) are used with Hayabusa and Chainsaw in Labs 2–3.

#### Requirements

Windows PowerShell 5.1 or PowerShell 7 **on Windows**; administrator rights to read the live Security log.

#### Installation (Windows)

```powershell
git clone https://github.com/sans-blue-team/DeepBlueCLI.git C:\Tools\DeepBlueCLI
# or download the ZIP from the repository page and run Unblock-File on the extracted .ps1 files
cd C:\Tools\DeepBlueCLI
Set-ExecutionPolicy RemoteSigned      # as Administrator, if scripts are disabled (see its Set-ExecutionPolicy README)
```

If antivirus complains after the download, its README explains why: the `evtx\` folder holds logs of real attacks (command lines included). The files themselves are harmless.

#### Configuration

| What | Where |
|---|---|
| Log to read | `.\DeepBlue.ps1 <file.evtx>` (it detects the log type) or `-log security\|system\|application\|powershell\|sysmon` for the live logs |
| Command-line regexes | `regexes.txt` (type `0` = commands, type `1` = service names) |
| Safelist | `safelist.txt` (regexes for commands to ignore) |
| Thresholds | Variables at the top of `Main` in `DeepBlue.ps1`: `$maxfailedlogons=5` (alert *above* 5 failures for one account, or in total across accounts), `$passsprayuniqusermax=6` and `$passsprayloginmax=6` (explicit-credential spraying, event 4648), `$minlength=1000` (long command lines), `$minpercent` and `$maxbinary` (obfuscation) |
| Output | PowerShell objects: `\| Format-List`, `\| Format-Table`, `\| ConvertTo-Csv`, `\| ConvertTo-Json`, `\| ConvertTo-Html`, `\| Out-GridView` |

#### Verify the installation

```powershell
.\DeepBlue.ps1 .\evtx\new-user-security.evtx      # should report "New User Created" and group additions
```

#### First use

```powershell
.\DeepBlue.ps1 E:\Cases\WS-ALICE\winevt\Logs\System.evtx | Format-List
.\DeepBlue.ps1 E:\Cases\WS-ALICE\winevt\Logs\Security.evtx | ConvertTo-Csv | Out-File ws-alice-security-deepblue.csv
.\DeepBlue.ps1 'E:\Cases\WS-ALICE\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx' | Format-List
```

**What its logic would report on WS-ALICE's logs** (worked out from `DeepBlue.ps1` and `regexes.txt`; not run):

| Event | DeepBlueCLI result | Why |
|---|---|---|
| 7045 `PSEXESVC`, image `%SystemRoot%\PSEXESVC.exe` | "Suspicious Service Command: **Metasploit-style %SYSTEMROOT% image path**" | Its regex `^%SYSTEMROOT%\\[a-zA-Z]{8}\.exe$` matches any 8-letter name, and `PSEXESVC` has 8 letters: the **right alert with the wrong story** (it was Sysinternals PsExec) |
| 104 log cleared | "System Log Clear" | Every 104 is reported, with that label, although the log cleared here was *Windows PowerShell* |
| 4104 `Set-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run …` | "Suspicious Command Line: Reference to registry run key (possible ASEP)" | Regex on script blocks run without a script path. Neither Hayabusa nor Chainsaw flags this one (Lab 4) |
| 4688 `"cmd"` started by `PSEXESVC.exe` | Nothing | Its "cmd.exe launched via PsExec" check needs `cmd.exe` in the command line, and this one is just `"cmd"` |
| 4625 × 3 (spray) | Nothing | 3 failures, 3 accounts: below the "more than 5" thresholds |
| 4688 `rclone`, `whoami`, `net`, hidden PowerShell | Nothing | No regex matches these, and none are long or obfuscated |

#### Troubleshooting

| Symptom | Fix |
|---|---|
| "running scripts is disabled on this system" | `Set-ExecutionPolicy RemoteSigned` (as admin) or run with `powershell -ExecutionPolicy Bypass -File .\DeepBlue.ps1 …` |
| "Get-WinEvent error" on a file | The script opens the file with `Get-WinEvent` first: check the path, and that it's a real `.evtx` file (not a CSV/XML export or a damaged copy) |
| No results on a log you know is bad | Thresholds and regexes are fixed; DeepBlueCLI isn't Sigma. Run Hayabusa/Chainsaw as well |
| Wrong fields in results for some events | It reads some fields by **position** (for 4688, `Data[8]` = command line, `Data[13]` = parent); events with a different field layout (other Windows versions, other providers) can be misread |
| Want it on Linux | Not supported in practice: run it in a Windows VM |

---

## Part 3: Hands-on labs

You'll run Hayabusa and Chainsaw on **real attack logs** (the sample files shipped with DeepBlueCLI: password spraying, SMB password guessing, a Metasploit PsExec attack, log tampering, a backdoor account), then on **WS-ALICE**'s logs from Day 14 (generated again by `scripts/mk_event_logs.py`), compare what each tool catches, and finally **write two rules** that close the gaps you find. To keep results reproducible, the labs build the tools from their **release tags** and pin the rule sets to fixed versions (SigmaHQ release `r2026-07-01` and a hayabusa-rules commit from 2026-10-08); with newer rules your counts will differ.

Run on Ubuntu 24.04 or SIFT.

```bash
sudo apt update && sudo apt install -y git curl libssl-dev perl build-essential
git -C ~/DFIR pull 2>/dev/null || git clone https://github.com/Mr-Phoenix07/DFIR.git ~/DFIR
mkdir -p ~/cases/LAB-015/{evidence,work,notes,samples,rules} ~/tools && cd ~/cases/LAB-015
export TZ=UTC
```

Build both tools and fetch the rules (10–15 minutes the first time):

```bash
command -v cargo > /dev/null || curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
[ -f ~/.cargo/env ] && . ~/.cargo/env
rustup update stable > /dev/null 2>&1
rustc --version
[ -d ~/tools/hayabusa-src ] || git -c advice.detachedHead=false clone -q --depth 1 --branch v4.1.0 https://github.com/Yamato-Security/hayabusa.git ~/tools/hayabusa-src
[ -d ~/tools/chainsaw-src ] || git -c advice.detachedHead=false clone -q --depth 1 --branch v2.16.5 https://github.com/WithSecureLabs/chainsaw.git ~/tools/chainsaw-src
(cd ~/tools/hayabusa-src && cargo build --release -q 2> /dev/null)
(cd ~/tools/chainsaw-src && cargo build --release -q 2> /dev/null)
if [ ! -d ~/tools/hayabusa-rules ]; then
  git init -q ~/tools/hayabusa-rules
  git -C ~/tools/hayabusa-rules fetch -q --depth 1 https://github.com/Yamato-Security/hayabusa-rules.git 04af3d207cae784183e0e5e82c1132ee866bbd67
  git -c advice.detachedHead=false -C ~/tools/hayabusa-rules checkout -q FETCH_HEAD
fi
[ -d ~/tools/sigma ] || git -c advice.detachedHead=false clone -q --depth 1 --branch r2026-07-01 https://github.com/SigmaHQ/sigma.git ~/tools/sigma
hayabusa() { ~/tools/hayabusa-src/target/release/hayabusa "$@"; }
chainsaw() { ~/tools/chainsaw-src/target/release/chainsaw "$@"; }
HR=~/tools/hayabusa-rules
CS=~/tools/chainsaw-src
hayabusa help | grep -m 1 Hayabusa
chainsaw --version
echo "SigmaHQ rules:        $(find ~/tools/sigma/rules -name '*.yml' | wc -l)"
echo "hayabusa-rules sigma: $(find $HR/sigma -name '*.yml' | wc -l) (builtin $(find $HR/sigma/builtin -name '*.yml' | wc -l), sysmon $(find $HR/sigma/sysmon -name '*.yml' | wc -l)), hayabusa: $(find $HR/hayabusa -name '*.yml' | wc -l)"
```

```
rustc 1.99.0 (b940084d7 2026-09-28)
Hayabusa v4.1.0 - Suzumushi Release
chainsaw 2.16.5
SigmaHQ rules:        3142
hayabusa-rules sigma: 4804 (builtin 2403, sysmon 2401), hayabusa: 196
```

(Your `rustc` version may be newer.) Note the numbers: about 3,100 Sigma rules upstream became **2,403 rules for built-in logs and 2,401 for Sysmon** in hayabusa-rules, plus 196 Hayabusa rules.

### Lab 1: Read a Sigma rule and its converted twin (15 min)

```bash
cat ~/tools/sigma/rules/windows/builtin/system/service_control_manager/win_system_service_install_sysinternals_psexec.yml
diff <(sed -n '/^detection:/,/^level:/p' ~/tools/sigma/rules/windows/process_creation/proc_creation_win_pua_rclone_execution.yml) \
     <(sed -n '/^detection:/,/^level:/p' $HR/sigma/builtin/process_creation/proc_creation_win_pua_rclone_execution.yml)
```

```
title: PsExec Service Installation
id: 42c575ea-e41e-41f1-b248-8093c3e82a28
status: test
description: Detects PsExec service installation and execution events
references:
    - https://www.jpcert.or.jp/english/pub/sr/ir_research.html
    - https://jpcertcc.github.io/ToolAnalysisResultSheet
author: Thomas Patzke
date: 2017-06-12
modified: 2023-08-04
tags:
    - attack.execution
    - attack.t1569.002
    - attack.s0029
logsource:
    product: windows
    service: system
detection:
    selection_eid:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
    selection_service:
        - ServiceName: 'PSEXESVC'
        - ImagePath|endswith: '\PSEXESVC.exe'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
1a2,4
>     process_creation:
>         EventID: 4688
>         Channel: Security
8,9c11,12
<         - Image|endswith: '\rclone.exe'
<         - Description: 'Rsync for cloud storage'
---
>         - NewProcessName|endswith: \rclone.exe
>         - Description: Rsync for cloud storage
12,26c15,29
<             - 'pass'
<             - 'user'
<             - 'copy'
<             - 'sync'
<             - 'config'
<             - 'lsd'
<             - 'remote'
<             - 'ls'
<             - 'mega'
<             - 'pcloud'
<             - 'ftp'
<             - 'ignore-existing'
<             - 'auto-confirm'
<             - 'transfers'
<             - 'multi-thread-streams'
---
>             - pass
>             - user
>             - copy
>             - sync
>             - config
>             - lsd
>             - remote
>             - ls
>             - mega
>             - pcloud
>             - ftp
>             - ignore-existing
>             - auto-confirm
>             - transfers
>             - multi-thread-streams
28c31
<     condition: selection_specific_options or all of selection_rclone_*
---
>     condition: process_creation and (selection_specific_options or all of selection_rclone_*)
```

- The **PsExec rule** matches a 7045 from the Service Control Manager whose service name is `PSEXESVC` **or** whose image ends in `\PSEXESVC.exe`. It's tagged with ATT&CK **T1569.002** (service execution) and software **S0029** (PsExec).
- The **rclone rule's** Hayabusa twin for built-in logs shows what "de-abstracting the logsource" means: it **adds** `EventID: 4688` and `Channel: Security`, renames **`Image` → `NewProcessName`**, and puts that new selection into the condition. (The quote differences are only YAML formatting.) The rule keeps `Description`, which 4688 doesn't have; it still works because of the OR.

### Lab 2: Hayabusa on real attack logs (20 min)

```bash
cd ~/cases/LAB-015/samples
for f in password-spray.evtx smb-password-guessing-security.evtx new-user-security.evtx disablestop-eventlog.evtx \
         metasploit-psexec-native-target-security.evtx metasploit-psexec-native-target-system.evtx; do
  curl -sSfL -o $f https://raw.githubusercontent.com/sans-blue-team/DeepBlueCLI/master/evtx/$f
done
sha256sum *.evtx | cut -c1-16,65- | tee ../notes/samples.sha256
cd ~/cases/LAB-015
hayabusa dfir-timeline -d samples -r $HR -c $HR/config -w -U -q -K -N -s -C -o work/samples-hayabusa.csv > /dev/null
python3 - work/samples-hayabusa.csv <<'EOF'
import csv, sys, collections
rows = list(csv.DictReader(open(sys.argv[1], encoding="utf-8-sig")))
order = ["crit", "high", "med", "low", "info"]
count = collections.Counter((r["Level"], r["RuleTitle"]) for r in rows)
print(f"{len(rows)} detections")
for (level, title), n in sorted(count.items(), key=lambda kv: (order.index(kv[0][0]), -kv[1], kv[0][1])):
    if level != "info":
        print(f"{level:<5} {n:>5}  {title}")
for r in rows:
    if r["RuleTitle"] in ("PW Spray", "PW Guessing"):
        print(r["Timestamp"][:19], r["RuleTitle"], "|", r["Details"])
EOF
```

```
7645e96c6d778f96  disablestop-eventlog.evtx
0c3547836951912d  metasploit-psexec-native-target-security.evtx
a6f285b356850395  metasploit-psexec-native-target-system.evtx
6f9fe51d0a5dec63  new-user-security.evtx
de910e6c86476db2  password-spray.evtx
19202585fe053e7b  smb-password-guessing-security.evtx
7445 detections
high   3561  Metasploit SMB Authentication
high      2  Important Log File Cleared
high      2  Log Cleared
high      2  Suspicious Service Path
high      1  Bad Opsec Defaults Sacrificial Processes With Improper Arguments
high      1  Meterpreter or Cobalt Strike Getsystem Service Installation - System
high      1  Privilege Escalation via Named Pipe Impersonation
high      1  Rundll32 Execution Without Parameters
high      1  Suspicious Service Name
high      1  User Added To Local Admin Grp
med       2  PW Spray
med       1  Event Log Service Startup Type Changed To Disabled
med       1  PW Guessing
med       1  Possible Metasploit Svc Installed
med       1  Rundll32 Execution With Uncommon DLL Extension
med       1  Susp CmdLine (Possible Meterpreter getsystem)
med       1  Uncommon Service Installation Image Path
low    3558  Logon Failure (Wrong Password)
low       2  Logon Failure (Unknown Reason)
low       1  A Member Was Added to a Security-Enabled Global Group
low       1  CMD Shell Output Redirect
low       1  Local User Account Created
low       1  Logon Failure (User Does Not Exist)
low       1  Possible LOLBIN
2016-09-19 16:50:06 PW Guessing | Count:3558 ¦ TargetUserName:Administrator ¦ TargetDomainName:. ¦ IpAddress:192.168.198.149 ¦ LogonType:3 ¦ ProcessName:- ¦ LogonProcessName:NtLmSsp
2019-04-30 19:27:02 PW Spray | Count:41 ¦ TargetUserName:Administrator/baker/bgalbraith/bgreenwood/bhostetler/bking/cdavis/celgee/cfleener/cmoody/cragoso/cspizor/dmashburn/dpendolino/drook/ebooth/econrad/edygert/eskoudis/gsalinas/jkulikowski/jlake/jleytevidal/jorchilles/jwright/kperryman/lpesce/lschifano/mdouglas/melliott/mtoussain/psmith/rbowes/sanson/sarmstrong/smisenar/ssims/tbennett/thessman/wstrzelec/zmathis ¦ IpAddress:172.16.144.128 ¦ Computer:DESKTOP-JR78RLP
2019-04-30 19:32:03 PW Spray | Count:14 ¦ TargetUserName:baker/bgalbraith/bgreenwood/bking/cragoso/cspizor/dmashburn/drook/edygert/jlake/jorchilles/mdouglas/smisenar/ssims ¦ IpAddress:172.16.144.128 ¦ Computer:DESKTOP-JR78RLP
```

7,445 detections from six small files. Read the summary, not the rows:

- **Volume isn't importance.** 3,561 "Metasploit SMB Authentication" (high) and 3,558 "Logon Failure (Wrong Password)" are *one* attack: 3,558 guesses at `Administrator` from 192.168.198.149, which the **correlation rule "PW Guessing"** sums up in a single line. Read that line first.
- **PW Spray** found 41, then 14, different user names tried with explicit credentials (4648) from 172.16.144.128 within 5 minutes.
- The rest are the classic **Metasploit PsExec** chain (random service name, `%SYSTEMROOT%\<8 letters>.exe`, the `getsystem` named pipe), **log clearing** and **event log service tampering**, and a **new administrator account**.

### Lab 3: Chainsaw on the same logs, and search (15 min)

```bash
chainsaw hunt samples -s ~/tools/sigma/rules --mapping $CS/mappings/sigma-event-logs-all.yml -r $CS/rules --jsonl -o work/samples-chainsaw.jsonl -q
python3 - work/samples-chainsaw.jsonl <<'EOF'
import json, sys, collections
hits = [json.loads(line) for line in open(sys.argv[1])]
order = ["critical", "high", "medium", "low", "info", "informational"]
count = collections.Counter((h["level"], h["name"], h["group"]) for h in hits)
print(f"{len(hits)} detections")
for (level, name, group), n in sorted(count.items(), key=lambda kv: (order.index(kv[0][0]), -kv[1], kv[0][1])):
    print(f"{level:<8} {n:>5}  {name}  [{'Sigma' if group == 'Sigma' else 'Chainsaw rule: ' + group}]")
EOF
chainsaw search -t 'Event.System.EventID: =7045' samples --jsonl -q | python3 -c '
import json, sys
for line in sys.stdin:
    e = json.loads(line)["Event"]
    print(e["System"]["TimeCreated_attributes"]["SystemTime"][:19], e["EventData"]["ServiceName"], "|", e["EventData"]["ImagePath"][:90])
'
```

```
3580 detections
critical     2  Security Audit Logs Cleared  [Chainsaw rule: Log Tampering]
critical     1  Meterpreter or Cobalt Strike Getsystem Service Installation  [Chainsaw rule: Service Installation]
critical     1  Windows Event Log Stopped  [Chainsaw rule: Service Tampering]
high      3561  Metasploit SMB Authentication  [Sigma]
high         2  Important Windows Eventlog Cleared  [Sigma]
high         2  System Logs Cleared  [Chainsaw rule: Log Tampering]
high         1  Meterpreter or Cobalt Strike Getsystem Service Installation - System  [Sigma]
high         1  Rundll32 Execution Without Parameters  [Sigma]
medium       1  Suspicious Commands Service Installation  [Chainsaw rule: Service Installation]
medium       1  Suspicious Paths Service Installation  [Chainsaw rule: Service Installation]
low          1  A Member Was Added to a Security-Enabled Global Group  [Sigma]
low          1  Local User Creation  [Sigma]
info         2  User Added to Local Group  [Chainsaw rule: Account Tampering]
info         1  Account Brute Force  [Chainsaw rule: Login Attacks]
info         1  New User Created  [Chainsaw rule: Account Tampering]
info         1  User Added to Global Group  [Chainsaw rule: Account Tampering]
2016-09-21T03:41:02 KgXItsbKgTJzdzwl | %SYSTEMROOT%\duKhLYUX.exe
2016-09-21T03:41:13 hgabms | cmd.exe /c echo hgabms > \\.\pipe\hgabms
```

- Chainsaw finds the same **core story** (Metasploit SMB authentication, the `getsystem` service, cleared logs, a stopped event log service, the new account), mixing **Sigma** results with its own **rule groups**.
- Its "Account Brute Force" rule (an aggregate) sums up the password guessing, but at level *info*. It has **nothing** for the 4648 password spray: Chainsaw doesn't run Sigma **correlation** rules, and Hayabusa's spray detection is one.
- `search` with a Tau expression lists **every** 7045 without any rule: the random service name `KgXItsbKgTJzdzwl` with a random 8-letter `%SYSTEMROOT%` executable, then the named-pipe `getsystem` trick (`hgabms`). That's DeepBlueCLI's "Metasploit-style" regex in action.

### Lab 4: WS-ALICE: what each tool catches, and what both miss (20 min)

```bash
python3 ~/DFIR/scripts/mk_event_logs.py evidence/WS-ALICE > /dev/null
L=evidence/WS-ALICE/Windows/System32/winevt/Logs
hayabusa dfir-timeline -d $L -r $HR -c $HR/config -w -U -q -K -N -s -C -o work/ws-alice-hayabusa.csv > /dev/null
chainsaw hunt $L -s ~/tools/sigma/rules --mapping $CS/mappings/sigma-event-logs-all.yml -r $CS/rules --jsonl -o work/ws-alice-chainsaw.jsonl -q
python3 - work/ws-alice-hayabusa.csv work/ws-alice-chainsaw.jsonl <<'EOF'
import csv, json, sys, collections
hits = collections.defaultdict(lambda: {"H": [], "C": []})
for r in csv.DictReader(open(sys.argv[1], encoding="utf-8-sig")):
    key = (r["Timestamp"][:19], int(r["EventID"]), int(r["RecordID"]))
    if r["Level"] != "info":
        hits[key]["H"].append(f'{r["RuleTitle"]} ({r["Level"]})')
for line in open(sys.argv[2]):
    h = json.loads(line)
    e = h["document"]["data"]["Event"]["System"]
    key = (h["timestamp"][:19].replace("T", " "), e["EventID"], e["EventRecordID"])
    if h["level"] not in ("info", "informational"):
        hits[key]["C"].append(f'{h["name"]} ({h["level"]})')
for key in sorted(hits):
    t, eid, rid = key
    if hits[key]["H"] or hits[key]["C"]:
        print(f"{t}  {eid}")
        print(f"    Hayabusa: {'; '.join(sorted(set(hits[key]['H']))) or '-'}")
        print(f"    Chainsaw: {'; '.join(sorted(set(hits[key]['C']))) or '-'}")
EOF
chainsaw analyse gaps $L/Security.evtx samples/new-user-security.evtx -q
```

```
2026-09-28 10:13:44  4104
    Hayabusa: Usage Of Web Request Commands And Cmdlets - ScriptBlock (med)
    Chainsaw: Usage Of Web Request Commands And Cmdlets - ScriptBlock (medium)
2026-09-29 01:04:10  4625
    Hayabusa: Logon Failure (Unknown Reason) (low)
    Chainsaw: -
2026-09-29 01:04:14  4625
    Hayabusa: Logon Failure (User Does Not Exist) (low)
    Chainsaw: -
2026-09-29 01:04:19  4625
    Hayabusa: Logon Failure (Wrong Password) (low)
    Chainsaw: -
2026-09-29 01:05:12  4688
    Hayabusa: PsExec Service Execution (med)
    Chainsaw: -
2026-09-29 01:05:12  7045
    Hayabusa: PSExec Lateral Movement (high); Suspicious Service Path (high)
    Chainsaw: PsExec Service Installation (medium); Suspicious Paths Service Installation (medium); Sysinternals PsExec Service Installation (medium)
2026-09-29 01:05:20  4688
    Hayabusa: Enumerate All Information With Whoami.EXE (med); Local Accounts Discovery (low)
    Chainsaw: -
2026-09-29 01:05:44  4688
    Hayabusa: Net.EXE Execution (low); Suspicious Group And Account Reconnaissance Activity Using Net.EXE (med)
    Chainsaw: -
2026-09-29 01:09:31  4688
    Hayabusa: Possible LOLBIN (low)
    Chainsaw: -
2026-09-29 01:12:47  4688
    Hayabusa: PUA - Rclone Execution (high)
    Chainsaw: -
2026-09-29 01:21:05  4688
    Hayabusa: Possible LOLBIN (low); Potentially Suspicious PowerShell Child Processes (med); Schedule Task Creation From Env Variable Or Potentially Suspicious Path Via Schtasks.EXE (med); Scheduled Task Creation Via Schtasks.EXE (low); Windows Shell/Scripting Processes Spawning Suspicious Programs (high)
    Chainsaw: -
2026-09-29 01:22:10  4688
    Hayabusa: New Service Creation Using Sc.EXE (low); Possible LOLBIN (low); Suspicious New Service Creation (high)
    Chainsaw: -
2026-09-29 01:22:10  7045
    Hayabusa: Service Installation in Suspicious Folder (med); Suspicious Service Path (high)
    Chainsaw: Service Installation in Suspicious Folder (medium); Suspicious Paths Service Installation (medium)
2026-09-29 01:22:11  4688
    Hayabusa: Possible LOLBIN (low)
    Chainsaw: -
2026-09-29 01:38:11  4104
    Hayabusa: Suspicious Eventlog Clear (med)
    Chainsaw: Suspicious Eventlog Clear (medium)
2026-09-29 01:38:12  104
    Hayabusa: Important Log File Cleared (high)
    Chainsaw: Important Windows Eventlog Cleared (high); System Logs Cleared (high)

=== evidence/WS-ALICE/Windows/System32/winevt/Logs/Security.evtx ===
[+] Channels seen:
    - Security: 23 records, RecordID 18234..18256, 2026-09-28T07:59:05+00:00 -> 2026-09-29T07:54:57+00:00
[+] No RecordID gaps detected
[!] 4 time gap(s) exceeding threshold:
    - Security: 2026-09-28T07:59:05+00:00 -> 2026-09-28T10:13:41+00:00 (8076s, RecordIDs 18235 -> 18236)
    - Security: 2026-09-28T10:13:41+00:00 -> 2026-09-28T18:02:38+00:00 (28137s, RecordIDs 18236 -> 18237)
    - Security: 2026-09-28T18:02:38+00:00 -> 2026-09-29T00:58:41+00:00 (24963s, RecordIDs 18237 -> 18238)
    - Security: 2026-09-29T01:22:11+00:00 -> 2026-09-29T07:54:57+00:00 (23566s, RecordIDs 18255 -> 18256)

=== samples/new-user-security.evtx ===
[+] Channels seen:
    - Security: 4 records, RecordID 1..4, 2013-10-23T16:22:39+00:00 -> 2013-10-23T16:22:40+00:00
[+] No RecordID gaps detected
[+] No suspicious time gaps detected
```

**What both tools caught:** the **PsExec service** (7045), the **service in a Temp folder** (`OneDriveSync`), the `Invoke-WebRequest` download, and **both traces of log clearing** (the 4104 `Clear-EventLog` and the System 104).

**What only Hayabusa caught, and why:** every **4688** finding: `PSEXESVC.exe` starting, rclone (high), `whoami /all`, `net localgroup administrators`, `sc create`, `schtasks /create` from PowerShell, the hidden PowerShell. Chainsaw loads the same Sigma rules, but its mapping looks for `Image`/`ParentImage`, which **4688 doesn't have** (it has `NewProcessName`/`ParentProcessName`), so the process rules can't match. On a machine with **Sysmon** (Day 16) Chainsaw would see them. Hayabusa's converted "builtin" rules (Lab 1) close that gap.

**What both missed:**

- **The 01:20:44 timestomping script.** SigmaHQ's "Powershell Timestomp" rule looks for `.CreationTime =`, `.LastWriteTime =` and `.LastAccessTime =`; alice's script used `.CreationTimeUtc =` and friends. A **variant** slips past a `contains` rule. (Lab 5 fixes this.)
- **The password spray.** Three accounts failed once each: Hayabusa logged three *low* "Logon Failure" lines, but its correlation rules need **5** guesses for one user (PW Guessing, 4625) or **5** names via explicit credentials (PW Spray, 4648), and Chainsaw's "Account Brute Force" needs **more than 5** failures for one user. Below the threshold, no alert. (Lab 5 again.)
- **The Run key** set by `Set-ItemProperty` at 01:21:29: Hayabusa lists it only as an *info* "PwSh Scriptblock" event and Chainsaw not at all. This is the one finding DeepBlueCLI's regex list would have made (Part 2).
- **The USB drive** (Partition 1006): Hayabusa lists it as an *info* "Device Conn" event, and Chainsaw has no rule for it. Plugging in a drive is usually normal: context, not rules, made it important on Day 14.
- **The scheduled task events** 4698 and 106 appear only at *info* level (Hayabusa's "Task Created" for both, Chainsaw's "T1053.005 - Scheduled Task was Created" for the 106), so they're not in this list. The **4688 `schtasks`** line is what drew attention.

**Gap analysis:** `analyse gaps` finds **no RecordID gaps** in WS-ALICE's Security log and lists **time gaps** over 30 minutes. In this lab log they're expected (it holds only the case's events, and 18:02–00:58 is the machine being off), but on a real workstation a Security log that goes silent for hours while the machine runs needs explaining. The Day 14 sample (the same file: its SHA-256 starts `6f9fe51d0a5dec63` in both labs) shows the limit of the method: Chainsaw checks the **record header numbers** (1–4), so it can't see that this exported file's `EventRecordID`s jump from 113 to 116.

### Lab 5: Close the gaps with your own rules (20 min)

First a Sigma rule for the timestomping variant. It spells out `EventID`/`Channel` (Hayabusa doesn't yet expand `logsource` itself; Chainsaw accepts both styles) and uses a regular expression so spacing doesn't matter:

```bash
cat > rules/posh_ps_timestomp_utc.yml <<'EOF'
title: PowerShell Sets File Timestamps Through the UTC Properties
id: 6b1f2a5e-8d0c-4c3e-9f7a-2e5d4c1b0a93
status: experimental
description: |
    Detects script blocks that assign CreationTimeUtc, LastWriteTimeUtc or LastAccessTimeUtc
    (timestomping). The SigmaHQ rule "Powershell Timestomp" looks for '.CreationTime =' and
    misses this variant.
references:
    - https://github.com/Mr-Phoenix07/DFIR
author: DFIR Daily (Day 15)
date: 2026-10-12
tags:
    - attack.defense-evasion
    - attack.t1070.006
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    ps_script:
        EventID: 4104
        Channel:
            - Microsoft-Windows-PowerShell/Operational
            - PowerShellCore/Operational
    selection:
        ScriptBlockText|re: '\.(Creation|LastWrite|LastAccess)TimeUtc\s*='
    condition: ps_script and selection
falsepositives:
    - Backup, sync or installer scripts that deliberately preserve file times
level: high
EOF
chainsaw lint rules --kind sigma 2>&1 | tail -n 1
chainsaw hunt $L samples -s rules --mapping $CS/mappings/sigma-event-logs-all.yml --jsonl -q | python3 -c '
import json, sys
for line in sys.stdin:
    h = json.loads(line)
    print("chainsaw:", h["timestamp"][:19], h["name"], "| record", h["document"]["data"]["Event"]["System"]["EventRecordID"])
'
hayabusa dfir-timeline -d $L -r rules -c $HR/config -w -U -q -K -N -C -o work/mine.csv > /dev/null
hayabusa dfir-timeline -d samples -r rules -c $HR/config -w -U -q -K -N -C -o work/mine-samples.csv > /dev/null
python3 - work/mine.csv work/mine-samples.csv <<'EOF'
import csv, sys
for path in sys.argv[1:]:
    rows = list(csv.DictReader(open(path, encoding="utf-8-sig")))
    print(f"hayabusa {path}: {len(rows)} detection(s)")
    for r in rows:
        print("   ", r["Timestamp"][:19], r["RuleTitle"], "| record", r["RecordID"])
EOF
```

```
[+] Validated 1 detection rules out of 1
chainsaw: 2026-09-29T01:20:44 PowerShell Sets File Timestamps Through the UTC Properties | record 905
hayabusa work/mine.csv: 1 detection(s)
    2026-09-29 01:20:44 PowerShell Sets File Timestamps Through the UTC Properties | record 905
hayabusa work/mine-samples.csv: 0 detection(s)
```

One rule file, two tools, one hit on WS-ALICE (the 01:20:44 script block) and **none** on the real attack samples. On a real case, also run a new rule over **known-good** logs from the same environment before trusting it.

Then a **correlation rule** for small sprays: three or more *different* user names failing a network logon from one IP within 5 minutes. A correlation rule refers to a base rule by its `name` (here in the same file, after `---`):

```bash
cat > rules/sec_4625_spray_small.yml <<'EOF'
title: Failed Network Logons for Several Accounts from One Source
id: 0c7c1f6e-3b5a-4d8e-9a21-7f4e2d6b8c15
status: experimental
description: |
    Three or more different account names fail a network logon from the same IP address
    within 5 minutes: password spraying or account guessing. A lower threshold than the
    built-in rules, for small or slow attacks.
author: DFIR Daily (Day 15)
date: 2026-10-12
tags:
    - attack.credential-access
    - attack.t1110.003
correlation:
    type: value_count
    rules:
        - failed_network_logon
    group-by:
        - IpAddress
    timespan: 5m
    condition:
        gte: 3
        field: TargetUserName
falsepositives:
    - A misconfigured script or service trying several accounts
level: medium
---
title: Failed Network Logon
id: 9d2e4b71-5c3a-4f0e-8b6d-1a7c3e5f9b24
name: failed_network_logon
status: experimental
description: A network (type 3) logon failed.
author: DFIR Daily (Day 15)
date: 2026-10-12
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4625
        LogonType: 3
    filter:
        IpAddress: '-'
    condition: selection and not filter
level: informational
EOF
hayabusa dfir-timeline -d $L -r rules/sec_4625_spray_small.yml -c $HR/config -w -U -q -K -N -C -o work/spray.csv > /dev/null
hayabusa dfir-timeline -d samples -r rules/sec_4625_spray_small.yml -c $HR/config -w -U -q -K -N -C -o work/spray-samples.csv > /dev/null
python3 - work/spray.csv work/spray-samples.csv <<'EOF'
import csv, sys
for path in sys.argv[1:]:
    rows = list(csv.DictReader(open(path, encoding="utf-8-sig")))
    print(f"hayabusa {path}: {len(rows)} detection(s)")
    for r in rows:
        print("   ", r["Timestamp"][:19], r["RuleTitle"], "|", r["Details"])
EOF
```

```
hayabusa work/spray.csv: 1 detection(s)
    2026-09-29 01:04:10 Failed Network Logons for Several Accounts from One Source | Count:3 ¦ TargetUserName:admin/administrator/bob ¦ IpAddress:10.20.30.45
hayabusa work/spray-samples.csv: 0 detection(s)
```

The spray from `LAPTOP-7Q2K` is now one *medium* alert naming all three accounts. It stays silent on the samples: the SMB guessing targets **one** account (the built-in "PW Guessing" covers it), and the big spray used **explicit credentials** (4648), not failed logons. A threshold is a trade-off: 3 catches small sprays, but on a busy network it will also catch people mistyping user names. Record that in the rule's `falsepositives` and in your notes.

To use these rules on every case, keep them in a folder of your own (versioned in git). Chainsaw takes `-s` more than once (`-s ~/tools/sigma/rules -s ~/my-rules`). Hayabusa takes one `-r` path: copy your folder into its rules directory (`update-rules` leaves new files alone) or run a second pass with `-r ~/my-rules`.

---

## ✅ Knowledge check

1. What do `logsource`, `detection` and `condition` each do in a Sigma rule?
2. Why did Chainsaw miss every 4688 detection on WS-ALICE that Hayabusa found? How would you fix it?
3. Name four reasons a detection rule can stay silent even though the activity happened.
4. Lab 2 produced 3,561 "Metasploit SMB Authentication" alerts. How do you deal with that volume?
5. What is a Sigma correlation rule, and why did no built-in rule flag WS-ALICE's three failed logons?
6. DeepBlueCLI would call the PSEXESVC service "Metasploit-style". Is that a false positive?
7. What does `chainsaw analyse gaps` look for, and what can it not see?
8. Before adding a new rule to your team's rule set, what should you test?

<details>
<summary><b>Answers</b></summary>

1. `logsource` says which logs the rule applies to (product plus service or category: the tool translates that into channels and event IDs). `detection` defines named selections of field/value matches (with modifiers). `condition` combines the selections with boolean logic (and, or, not, `1 of`, `all of`).
2. Sigma process rules use Sysmon field names (`Image`, `ParentImage`). Chainsaw's mapping passes those names through, but Security 4688 calls the fields `NewProcessName`/`ParentProcessName`, so those rules can never match 4688. Fixes: collect Sysmon logs (Day 16), use Hayabusa's converted builtin rules, or extend Chainsaw's mapping for 4688.
3. The log isn't enabled (4688 auditing, script block logging, Sysmon); the tool can't map the fields; the attacker used a variant the rule doesn't cover (e.g. `CreationTimeUtc` instead of `CreationTime`); the activity stayed below a threshold or outside a correlation time window. Also: the rule wasn't loaded (level, status or noisy filters), or the logs rolled over.
4. Group by rule title (and host and source IP) and treat it as **one** finding: a large-scale authentication attack from one source. Read the correlation summary ("PW Guessing", Count 3,558) first; check whether any of those attempts **succeeded** (4624 from the same IP). Don't let it bury the single-event alerts.
5. A rule that counts or combines matches of other rules over a timespan (`event_count`, `value_count`, `temporal`). The built-in ones need 5 wrong passwords for one user (PW Guessing) or 5 user names in explicit-credential events (PW Spray) within 5 minutes; WS-ALICE had 3 failures for 3 different users.
6. It's a true positive (a remote-execution service was installed, which matters) with a **wrong label**: the 8-letter regex was written for Metasploit's random names and happens to match Sysinternals' `PSEXESVC`. The finding stays; the attribution changes.
7. RecordID gaps (records missing from the middle of a log, e.g. selective deletion) and long time gaps (logging stopped). It reads the **record header** numbers of the file in front of it, so it can't see records removed before a log was exported or saved (when the file was renumbered), and a time gap may simply mean the machine was off.
8. That it **loads** (`chainsaw lint`, a Hayabusa test run), that it **fires** on a known-bad sample (here WS-ALICE's event), and that it **stays quiet** on known-good and unrelated logs (here the attack samples, and ideally normal logs from your environment). Record its false positives and level honestly.

</details>

---

## 📚 Further reading

- SigmaHQ, *Sigma specification* and *Sigma rules* (https://github.com/SigmaHQ/sigma-specification, https://github.com/SigmaHQ/sigma), including the correlation rules specification
- Yamato Security, *Hayabusa documentation* (https://yamato-security.github.io/hayabusa/), especially "Sigma curation" (why rules are converted per log source) and "Correlations"
- WithSecure Labs, *Chainsaw* README: hunting logic and the mapping file
- Eric Conrad, *DeepBlueCLI* README and the SANS course material it comes from
- MITRE ATT&CK techniques T1110.003 (password spraying), T1569.002 (service execution) and T1070.006 (timestomping)

---

## ⏭️ Tomorrow: Day 16

**Sysmon and enhanced logging for investigators.** Tools: **Sysmon**, **sigma-cli (pySigma)**, **Zircolite**.
Today showed what Security 4688 can't tell a rule (no hashes, no original file names, no network connections). Tomorrow you'll see what Sysmon adds, convert Sigma rules for other back-ends with sigma-cli, and hunt with Zircolite.

---

<sub>Part of the <a href="../README.md">DFIR Daily</a> series · <a href="../CURRICULUM.md">Full 60-day curriculum</a> · For educational and authorised use only.</sub>
