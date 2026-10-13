# Day 16: Sysmon & Enhanced Logging for Investigators

> **Phase 2: Windows Forensics** · **Level:** 🟡 Intermediate · **Time:** ~4 hours (reading + labs) · **Posted:** 2026-10-13
>
> **Tools today:** 🛠️ Sysmon (Windows and Linux) · 🛠️ sigma-cli (pySigma) · 🛠️ Zircolite

---

## 🎯 Learning objectives

By the end of today you will be able to:

1. Say what Windows records **by default**, what it records only when **enabled**, and how to check what was enabled on a machine you're investigating.
2. Explain how **Sysmon** works (driver, service, configuration, ProcessGuid) and what each of its main event IDs proves.
3. **Read a Sysmon configuration** and predict what it will and won't log, then confirm it against the log itself.
4. Use **sigma-cli** to check a rule and convert it for different back-ends and log sources (pipelines).
5. Hunt Sysmon and Windows logs with **Zircolite**, using ready-made rulesets and your own Sigma rules.

---

## Part 1: The lesson

On Days 14 and 15 the Security, System and PowerShell logs told most of WS-ALICE's story, but with gaps. Nothing said **where rclone sent the files**. Nothing showed the **timestomping** except a PowerShell script block. The 4688 events had **no hashes**, so you couldn't prove which rclone binary ran, and Chainsaw's process rules missed them all. Those gaps aren't bad luck; they're the limits of default logging. Today is about the logging that fills them, and about knowing which of it existed on the machine in front of you.

### 1.1 What default logging can't tell you

| Question | Windows built-in logging | With Sysmon (if the config keeps it) |
|---|---|---|
| Which program ran, exactly? | 4688 gives the path, only if *Process Creation* auditing is on (it's off by default on Windows clients). No hash | **1**: path, **hashes**, **OriginalFileName** (survives renaming), version info, integrity level |
| Who started it, with what? | 4688 gives the parent's path; the command line only if a separate policy is on | **1**: parent image **and** parent command line, linked by **ProcessGuid** |
| How long did it run? | 4689 (rarely enabled) | **5** process terminated |
| Where did it connect? | Nothing by default (Windows Filtering Platform events 5156 are possible but very noisy) | **3** network connection, **22** DNS query, each tied to the process |
| What did it write or change? | Object Access auditing (4663/4657) needs SACLs on each file or key | **11** file created, **12/13/14** registry, **15** alternate data streams (e.g. `Zone.Identifier`), **23/26** deletes |
| Did it fake timestamps? | Nothing | **2** file creation time changed |
| Did it inject into or read another process? | Nothing | **8** CreateRemoteThread, **10** process access (e.g. LSASS) |
| What did PowerShell run? | 4104 with Script Block Logging (Windows also logs some suspicious blocks on its own as warnings) | Not Sysmon's job: keep 4104 on as well |

### 1.2 The enhanced-logging checklist

When you **set up** a network, or **recommend** fixes after an incident, these are the levers. When you **investigate**, these are the things to check first, because they decide what evidence can exist.

| Lever | How it's set | Investigator's check |
|---|---|---|
| Advanced audit policy | Group Policy, or `auditpol /set /subcategory:"Process Creation" /success:enable` | Live: `auditpol /get /category:*`. Offline: it's stored in the SECURITY hive (`Policy\PolAdtEv`, binary); easier to look at which event IDs the Security log actually contains |
| Command lines in 4688 | Policy *Include command line in process creation events*, or `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit` value `ProcessCreationIncludeCmdLine_Enabled` = 1 | The value in the SOFTWARE hive; whether 4688 events have a `CommandLine` |
| PowerShell logging | `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging` `EnableScriptBlockLogging` = 1 (4104); `ModuleLogging` (4103); `Transcription` (text transcripts to a folder) | The same keys in the SOFTWARE hive; transcript folders on disk |
| Log size and retention | `wevtutil sl Security /ms:<bytes>`; the Security log is only 20 MB by default on Windows 10/11 | `wevtutil gl <log>` (live), the oldest record in each log: a small log on a busy machine may hold only hours |
| Central collection | Windows Event Forwarding or a SIEM agent | Ask for the SIEM copy: it survives local clearing (Day 15's 104/1102) |
| **Sysmon** | Installed with a configuration file (1.3) | Is the service present (`Sysmon64`, driver `SysmonDrv`)? Which config was loaded (event 16, or `sysmon -c` on a live host)? |

**Absence of evidence isn't evidence of absence.** "No 4688 for rclone" means nothing if process auditing was off. Write down, early in every case, what logging existed and from when.

### 1.3 Sysmon: how it works

**System Monitor (Sysmon)** is a free Sysinternals tool: a **driver** (`SysmonDrv`) that watches the system from early in boot, and a **service** (`Sysmon64` on 64-bit Windows) that writes events to **`Microsoft-Windows-Sysmon/Operational`**. Everything it does is driven by an **XML configuration**: which events to keep, which hashes to compute, and (in recent versions) which files to archive or block. The service runs as a protected process; Sysmon doesn't try to hide itself.

| ID | Event | Why investigators want it |
|---|---|---|
| 1 | Process creation | Full command lines, hashes, OriginalFileName, parent, ProcessGuid, LogonGuid |
| 2 | File creation time changed | Timestomping (many installers do it legitimately too) |
| 3 | Network connection | Process ↔ IP/port, including C2 and exfiltration (off unless the config enables it) |
| 4 / 16 | Sysmon service state / configuration changed | When Sysmon started or stopped, and which configuration was loaded (with its hash) |
| 5 | Process terminated | Process lifetime: ran for half a second or for hours? |
| 6 / 7 | Driver / image (DLL) loaded | Malicious drivers, DLL side-loading (image load is very noisy) |
| 8 / 10 | CreateRemoteThread / process access | Injection, credential theft from LSASS (`GrantedAccess`) |
| 11 | File created | Dropped tools, scripts, scheduled task files |
| 12 / 13 / 14 | Registry key create/delete, value set, rename | Run keys, services, COM hijacks |
| 15 | File stream created | `Zone.Identifier` (where a download came from: Day 10) |
| 17 / 18 | Named pipe created / connected | PsExec-style tools, C2 frameworks |
| 19 / 20 / 21 | WMI filter / consumer / binding | WMI persistence |
| 22 | DNS query | Which process asked for which name |
| 23 / 26 | File deleted (archived / logged only) | Deleted tools; 23 can keep a copy of the file |
| 25 | Process tampering | Process hollowing and similar |
| 27 / 28 / 29 | Executable blocked / shredding blocked / executable detected | Sysmon's blocking features |
| 255 | Error | Sysmon itself had a problem |

**Two GUIDs make Sysmon events joinable.** Windows reuses process IDs; Sysmon gives every process a **ProcessGuid**, repeated as `ParentProcessGuid` in its children and in every event the process causes (network, file, registry). In every real sample in today's labs, the GUID's **second and third groups are the process start time** (Unix seconds, low and high halves), and the **LogonGuid ends with the LogonId** (little-endian): you can decode them (Lab 3).

**The configuration decides everything.** Each event type has a filter tag (`ProcessCreate`, `NetworkConnect`, `FileCreateTime`, ...) with `onmatch="include"` (log only matches) or `onmatch="exclude"` (log everything except matches); excludes win over includes. Rules test fields with conditions (`is`, `contains`, `begin with`, `end with`, `image`, `contains any`, ...), combine with OR by default or AND inside a `RuleGroup`/`Rule` with `groupRelation="and"`, and a rule's `name` is written into the event's **RuleName** field, so the log tells you *why* it kept an event. Popular starting points: **SwiftOnSecurity's sysmon-config** (its configuration's last version is dated 2021-07-08; still widely deployed) and **Olaf Hartong's sysmon-modular** (maintained, ATT&CK-mapped, built from modules). Every config has blind spots; Lab 2 finds them before Lab 3 hits them.

**Sysmon for Linux** uses the same configuration format and event schema, collects through eBPF, and writes each event as an XML line to **syslog**. It covers process creation and termination, network connections, file creation and deletion, raw disk reads and ptrace (process access).

**From the attacker's side:** Sysmon is easy to spot (service and driver names, its event log), and an administrator can read its configuration (`sysmon -c`, or the binary rules under `HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters`) to find its blind spots, unload or uninstall it, or clear its log (the real samples in Lab 5 start with `wevtutil cl Microsoft-Windows-Sysmon/Operational`). The configuration entry `DriverName` lets defenders rename the driver. Signs of tampering: event **4** (stopped), **16** (configuration changed), **255** (errors), System 7036/7040 for the Sysmon service, a cleared log (104), or a log that goes quiet while the machine is clearly in use.

### 1.4 Sigma pipelines: one rule, many log formats

Day 15 showed the problem: a Sigma `process_creation` rule uses Sysmon field names (`Image`, `ParentImage`). A **processing pipeline** in pySigma rewrites a rule for a particular log source *before* it's converted: the **`sysmon`** pipeline adds `EventID: 1` (and the Sysmon channel with `windows-logsources`), while **`windows-audit`** turns the same rule into **4688** with `NewProcessName`/`ParentProcessName`. **sigma-cli** is the command-line front end for pySigma: it checks rules and converts them, through pipelines, into Splunk, Elastic, SQLite and many other query languages. **Zircolite** uses the same library: it loads logs into SQLite, converts Sigma rules into SQL with pySigma's SQLite back-end, and runs them. Choose the wrong pipeline and a perfectly good rule matches nothing (Lab 5).

---

## Part 2: Tools

---

### 🛠️ Tool 1: Sysmon (Windows) and Sysmon for Linux

| | |
|---|---|
| **What** | Sysinternals' System Monitor: a driver and service that log process, network, file, registry and other activity to the event log (Windows) or syslog (Linux), filtered by an XML configuration |
| **Why in DFIR** | The richest host telemetry most organisations have: hashes and full command lines for every process, network and DNS per process, persistence, injection, timestomping. Ask for it in every Windows case; recommend it after every case |
| **Platforms** | Windows clients and servers (the current page lists Windows 11 and Windows Server 2019 or later for v15.22); Linux (Sysmon for Linux, eBPF). **Windows Sysmon not run here** (Windows-only, and the download site isn't reachable from this lab environment). **Sysmon for Linux 1.5.3 was installed and run on Ubuntu 24.04** (Lab 1) |
| **Licence** | Sysmon: free, under the Sysinternals licence terms. Sysmon for Linux: MIT, eBPF programs GPLv2 |
| **Home** | https://learn.microsoft.com/sysinternals/downloads/sysmon · https://github.com/microsoft/SysmonForLinux · configs: https://github.com/SwiftOnSecurity/sysmon-config, https://github.com/olafhartong/sysmon-modular |

#### Requirements

Windows: administrator rights; a configuration file (installing without one gives the defaults: process images hashed with SHA1 and no network logging). Linux: root, a kernel with eBPF (BTF is used when available), and syslog (rsyslog writes `/var/log/syslog` on Ubuntu).

#### Installation

```powershell
# Windows (run as Administrator): download https://download.sysinternals.com/files/Sysmon.zip, extract it, then
.\Sysmon64.exe -accepteula -i .\sysmonconfig-export.xml      # install the service and driver with a config
.\Sysmon64.exe -c                                             # dump the active configuration
.\Sysmon64.exe -c .\new-config.xml                            # load a new configuration (logs event 16)
.\Sysmon64.exe -u                                             # uninstall
```

```bash
# Ubuntu (the INSTALL.md route; Debian, Fedora, RHEL and SUSE use their own packages-microsoft-prod)
wget -q https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
sudo apt-get update && sudo apt-get install -y sysmonforlinux
sudo sysmon -accepteula -i config.xml                         # same options as on Windows
```

#### Configuration

| Item | Meaning |
|---|---|
| `<Sysmon schemaversion="4.90">` | Schema of the config; `sysmon -s` prints the schema your binary supports (sysmon-modular's notes: Sysmon 15 uses 4.90, 15.21 uses 4.91) |
| `<HashAlgorithms>` | `MD5`, `SHA1`, `SHA256`, `IMPHASH` or `*` |
| `<EventFiltering>` | One filter tag per event type, `onmatch="include"` or `"exclude"`, rules inside; `RuleGroup`/`Rule` with `groupRelation="and"` for AND |
| Conditions | `is`, `is not`, `is any`, `contains`, `contains any`, `contains all`, `excludes`, `begin with`, `end with`, `not begin with`, `not end with`, `less than`, `more than`, `image` (all case-insensitive) |
| `name="..."` on a rule | Copied into the event's **RuleName** |
| `ArchiveDirectory`, `CopyOnDelete*` | Where event 23 keeps copies of deleted files |
| `DnsLookup`, `CheckRevocation`, `DriverName` | Reverse DNS, signature revocation checks, renamed driver |
| Log size (Windows) | `wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:<bytes>`: size it for the retention you need |

Use `sysmon -? config` for the full configuration help.

#### Verify the installation

```powershell
Get-Service Sysmon64
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 5 | Format-List Id, TimeCreated, Message
```

```bash
sudo sysmon -c | sed -n '/^Rule configuration/,$p'           # Linux: the rules Sysmon is running with
sudo grep ' sysmon: ' /var/log/syslog | tail -n 3              # recent events
```

#### First use

Install with a published configuration, look at a day's worth of events, then tune: exclude what's noisy *and* understood, include what your threat model needs. On a case, export the log (`wevtutil epl Microsoft-Windows-Sysmon/Operational C:\Cases\sysmon.evtx`) or collect `Microsoft-Windows-Sysmon%4Operational.evtx` with your triage tool (Day 8), along with the configuration that was running (`Sysmon64.exe -c > sysmon-config.txt`).

#### Troubleshooting

| Symptom | Fix |
|---|---|
| "Incorrect or missing schema version" / config rejected | Set `schemaversion` to one your binary supports (`sysmon -s`); use a config built for your Sysmon version (sysmon-modular publishes several) |
| An event type never appears | The config doesn't keep it: check the filter tag (an empty `include` keeps nothing); some events are off by default (network, image load) |
| Far too many events | Add `exclude` rules for understood noise; image load (7) and process access (10) need careful filters |
| Linux: `Telemetry failed to start: eBPF program could not be attached` | The kernel's tracing filesystem isn't available (seen in containers); on a normal VM it's mounted at `/sys/kernel/tracing` |
| Linux: `System has not been booted with systemd` | `sysmon -i` registers a systemd service; without systemd (containers) the service has to be started by hand |
| Linux: event 16 shows `ConfigurationFileHash=-` | Pass the configuration with an absolute path (the service can't hash a relative path) |
| Linux: long events cut off | Raise your syslog daemon's message size, or use `<FieldSizes>` in the config (Sysmon for Linux README) |

---

### 🛠️ Tool 2: sigma-cli (pySigma)

| | |
|---|---|
| **What** | The Sigma project's command-line interface to pySigma: lists, checks and converts Sigma rules |
| **Why in DFIR** | Turn the rules you used on Day 15 (and your own) into queries for the SIEM where the logs actually are (Splunk, Elastic, Microsoft, Google SecOps, ...); validate rules before sharing them; see exactly what a rule looks for after field mapping |
| **Platforms** | Anywhere Python 3 runs. **sigma-cli 3.1.0 with pySigma 1.5.1 run on Ubuntu 24.04** |
| **Licence** | LGPL-2.1 (sigma-cli and pySigma); back-ends and pipelines are separate packages with their own licences |
| **Home** | https://github.com/SigmaHQ/sigma-cli · https://github.com/SigmaHQ/pySigma |

#### Requirements

Python 3 and pip or pipx; one **back-end** plugin per target query language, plus the **pipelines** for your log sources.

#### Installation

```bash
python3 -m pipx install sigma-cli               # or: python -m pip install sigma-cli (in a virtual environment)
sigma plugin list                               # back-ends and pipelines you can add
sigma plugin install splunk                     # one back-end; also e.g. elasticsearch, sqlite, sysmon, windows
```

macOS: `brew install sigma-cli`. Windows: `python -m pip install sigma-cli`. In the labs the plugins are installed with pip at fixed versions, so the output can't change under you.

#### Configuration

| Command | Meaning |
|---|---|
| `sigma list targets` / `sigma list pipelines` | What's installed |
| `sigma convert -t TARGET -p PIPELINE [-p ...] RULES` | Convert a file or folder; `-o FILE` or `-od DIR` to save, `-f FORMAT` for a back-end's output formats (e.g. Splunk saved searches), `-s` to skip rules a back-end can't handle |
| `sigma check RULES` | Parse and validate rules (identifiers, file names, tags, conditions, ...). `-x VALIDATOR` skips one |
| `sigma plugin install/uninstall/upgrade NAME` | Manage plugins |

#### Verify the installation

```bash
sigma version
sigma list targets
```

#### First use

```bash
sigma convert -t splunk -p sysmon -p splunk_windows ~/tools/sigma/rules/windows/process_creation/proc_creation_win_pua_rclone_execution.yml
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| `... processing pipeline required` | Most targets need a pipeline (`-p sysmon`, `-p windows-audit`, a back-end's own); `--without-pipeline` only if you know why |
| `Failed to load MITRE ATT&CK data` (or D3FEND) during `check` | The tag validators download MITRE data from GitHub. Offline, skip them: `-x attacktag -x d3_fendtag` |
| A rule converts but never matches | Wrong pipeline for the logs (Lab 5), or field names your SIEM doesn't use: add or write a pipeline |
| Plugin incompatible | `sigma plugin list` shows compatibility; upgrade sigma-cli and the plugin together |

---

### 🛠️ Tool 3: Zircolite

| | |
|---|---|
| **What** | A standalone Sigma-based detection tool by wagga40 for EVTX, Auditd, Sysmon for Linux, XML, CSV and JSON logs: it flattens events into SQLite and runs Sigma rules as SQL |
| **Why in DFIR** | Fast offline triage of large log sets with SigmaHQ rules (ready-made rulesets or native YAML through pySigma pipelines), Sigma correlation rules, Linux logs as well as Windows, exports for Splunk, Elastic, Timesketch and the ATT&CK Navigator, and a browser "Viewer" package. Also runs from KAPE and Velociraptor |
| **Platforms** | Linux, macOS, Windows (release binaries, Docker or source). **Built from v4.5.0 in a Python virtual environment and run on Ubuntu 24.04** |
| **Licence** | Code under the GNU LGPL; rulesets keep their sources' licences (SigmaHQ: DRL 1.1) |
| **Home** | https://github.com/wagga40/Zircolite · docs: https://wagga40.github.io/Zircolite/ |

#### Requirements

Binary or Docker: nothing else. From source: Python 3.10 or later (the README recommends 3.11 to 3.14; free-threaded builds aren't supported yet) and a C compiler, which builds the faster native flattening kernel (without one it falls back to Python).

#### Installation

```bash
# From source with PDM or uv (the README's routes)
git clone https://github.com/wagga40/Zircolite.git && cd Zircolite
pdm install                                   # or: uv sync
pdm run python3 zircolite.py --version

# What the labs do: a plain virtual environment and pip, at a release tag
sudo apt install -y python3-venv python3-dev build-essential
git clone --depth 1 --branch v4.5.0 https://github.com/wagga40/Zircolite.git ~/tools/Zircolite
python3 -m venv ~/tools/zircolite-venv
~/tools/zircolite-venv/bin/pip install -e ~/tools/Zircolite   # -e builds the native kernel inside the source tree
~/tools/zircolite-venv/bin/python -m zircolite --version
```

Windows/macOS/Linux binaries: download the zip for your platform (VER = e.g. 4.5.0) from https://github.com/wagga40/Zircolite/releases and run `Zircolite` / `Zircolite.exe`. Docker: `docker pull wagga40/zircolite:latest`.

#### Configuration

| Option | Meaning |
|---|---|
| `--events PATH` (`-e`, `--evtx`) | A log file or folder (format detected); `-s`/`-a` select or avoid file names |
| `-r RULESET` | A Zircolite JSON ruleset (`rules/rules_windows_sysmon.json`, `rules_windows_generic.json`, `rules_windows_merged.json` (default), `rules_linux.json`) or native Sigma YAML (file or folder); repeatable |
| `-p PIPELINE` | pySigma pipelines for native YAML: `sysmon`, `windows-logsources`, `windows-audit` (`-pl` lists them) |
| `-S` / `-AU` / `-j` / `-x` / `--csv-input` | Sysmon for Linux / Auditd / JSON lines / XML / CSV input |
| `-o FILE`, `--csv`, `-l LOG`, `-n` | Detections file (default `detected_events.json`), CSV, log file, write neither |
| `--min-level LEVEL`, `-R TITLE` | Only rules at or above a level; drop rules by title |
| `-A`, `-B` | Only events after / before a UTC time |
| `-t TEMPLATE -T OUT`, `--timesketch`, `--navigator-output`, `--package` | Exports and the offline Viewer |
| `-U` | Update the rulesets in `rules/` (checked against the rules repository's manifest) |
| `-q` | Quiet: only the summary panel |

#### Verify the installation

```bash
~/tools/zircolite-venv/bin/python -m zircolite --version       # Zircolite - v4.5.0
```

The summary panel's **Flattening** row says `auto → cython` when the native kernel was built.

#### First use

```bash
~/tools/zircolite-venv/bin/python -m zircolite --events /cases/WS-ALICE/winevt/Logs \
    -r ~/tools/Zircolite/rules/rules_windows_merged.json -o ws-alice-zircolite.json
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| `auto → python (native extension unavailable ...)` | No C compiler when it was installed, or the source tree was used without building: install `build-essential python3-dev` and reinstall (`pip install -e`, `pdm install`, `uv sync`) |
| Detections on the wrong event types | A ruleset or pipeline without EventID conditions (Lab 1 shows a "reverse shell" rule matching process events): look at each match's `EventID` before believing it |
| No detections with native Sigma rules | Missing or wrong `-p` pipeline for the logs (Lab 5) |
| Slow, or too many detections | Build your own ruleset; `--min-level medium`; `-R` noisy rules; `--profile-rules` to find slow ones |
| Python version errors | Use Python 3.11 to 3.14 (not free-threaded), or a release binary |

---

## Part 3: Hands-on labs

You'll install and configure **Sysmon for Linux** and watch it log a small attack; read a real **Sysmon configuration** to predict its blind spots; analyse **WS-ALICE's Sysmon log** (IT had Sysmon with SwiftOnSecurity's configuration on the machine; the log was exported separately from the Day 14 collection); convert rules with **sigma-cli**; and hunt with **Zircolite** on WS-ALICE and on two **real attack logs** (Metasploit and Sliver, from DeepBlueCLI's sample folder). Tools, rule sets and the SwiftOnSecurity configuration are pinned to fixed versions, so your output should match.

Run on Ubuntu 24.04 or SIFT (with sudo).

```bash
sudo apt update && sudo apt install -y git curl lsb-release python3-venv python3-dev build-essential rsyslog
git -C ~/DFIR pull 2>/dev/null || git clone https://github.com/Mr-Phoenix07/DFIR.git ~/DFIR
mkdir -p ~/cases/LAB-016/{evidence,work,notes,samples,rules} ~/tools && cd ~/cases/LAB-016
export TZ=UTC
```

Install Zircolite (release v4.5.0) and sigma-cli with its plugins at fixed versions, and fetch SigmaHQ release `r2026-07-01` (a few minutes):

```bash
[ -d ~/tools/Zircolite ] || git -c advice.detachedHead=false clone -q --depth 1 --branch v4.5.0 https://github.com/wagga40/Zircolite.git ~/tools/Zircolite
[ -d ~/tools/zircolite-venv ] || python3 -m venv ~/tools/zircolite-venv
~/tools/zircolite-venv/bin/pip install -q -e ~/tools/Zircolite 2> /dev/null
[ -d ~/tools/sigma-venv ] || python3 -m venv ~/tools/sigma-venv
~/tools/sigma-venv/bin/pip install -q sigma-cli==3.1.0 pysigma==1.5.1 pysigma-backend-splunk==2.1.0 \
    pysigma-backend-sqlite==2.0.0 pysigma-pipeline-sysmon==2.0.0 pysigma-pipeline-windows==2.0.1 2> /dev/null
[ -d ~/tools/sigma ] || git -c advice.detachedHead=false clone -q --depth 1 --branch r2026-07-01 https://github.com/SigmaHQ/sigma.git ~/tools/sigma
zircolite() { ~/tools/zircolite-venv/bin/python -m zircolite "$@"; }
sigma() { ~/tools/sigma-venv/bin/sigma "$@"; }
ZR=~/tools/Zircolite/rules
zircolite --version 2>&1 | grep -m 1 -o 'Zircolite - v[0-9.]*'
sigma version | cut -d ' ' -f 1
~/tools/zircolite-venv/bin/python -c 'import zircolite._flatten_native; print("Zircolite native kernel: built")'
```

```
Zircolite - v4.5.0
3.1.0
Zircolite native kernel: built
```

### Lab 1: Install, configure and watch Sysmon for Linux (30 min)

Register Microsoft's package feed and install `sysmonforlinux`, then write a small configuration: log processes whose command line contains `day16`, connections made by `curl` **and** to port 8016 (an AND rule group), files created under `/tmp/day16/`, and **no** process terminations (an empty include):

```bash
wget -q https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb -O /tmp/packages-microsoft-prod.deb
sudo dpkg -i /tmp/packages-microsoft-prod.deb > /dev/null
sudo apt-get update -qq && sudo apt-get install -y -qq sysmonforlinux > /dev/null
sysmon -? 2>&1 | grep -m 1 '^Sysmon v'
cat > work/day16-linux.xml <<'EOF'
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="include">
        <CommandLine name="lab-cmd" condition="contains">day16</CommandLine>
      </ProcessCreate>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <ProcessTerminate onmatch="include"/>
    </RuleGroup>
    <RuleGroup name="lab-net" groupRelation="and">
      <NetworkConnect onmatch="include">
        <Image condition="end with">/curl</Image>
        <DestinationPort condition="is">8016</DestinationPort>
      </NetworkConnect>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename name="lab-drop" condition="begin with">/tmp/day16/</TargetFilename>
      </FileCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
EOF
sudo sysmon -accepteula -i "$PWD/work/day16-linux.xml" > work/sysmon-install.txt 2>&1
sudo sysmon -c | sed -n '/^Rule configuration/,$p'
```

```
Sysmon v1.5.3 - Monitors system events
Rule configuration (version 4.90):
 - ProcessCreate                      onmatch: include   combine rules using 'Or'
	CommandLine                    filter: contains     value: 'day16'
 - NetworkConnect                     onmatch: include   combine rules using 'And'
	Image                          filter: end with     value: '/curl'
	DestinationPort                filter: is           value: '8016'
 - ProcessTerminate                   onmatch: include   combine rules using 'Or'
 - FileCreate                         onmatch: include   combine rules using 'Or'
	TargetFilename                 filter: begin with   value: '/tmp/day16/'
```

`sysmon -c` shows the rules as Sysmon understood them: the network rules are combined with **And**, and `ProcessTerminate` has an include filter with no rules, so it keeps nothing. Now play a tiny "download and run" attack: a local web server, `curl` fetches a script into `/tmp/day16`, `bash` runs it, and the script drops a file:

```bash
rm -rf /tmp/day16 /tmp/www16 && mkdir -p /tmp/day16 /tmp/www16
printf 'echo "dropped by stage.sh" > /tmp/day16/flag.txt\n' > /tmp/www16/stage.sh
python3 -m http.server 8016 --bind 127.0.0.1 --directory /tmp/www16 > /dev/null 2>&1 &
srv=$!; sleep 1
start=$(sudo wc -l < /var/log/syslog)
curl -s -o /tmp/day16/stage.sh http://127.0.0.1:8016/stage.sh
bash /tmp/day16/stage.sh
sleep 2
sudo tail -n +$((start + 1)) /var/log/syslog | grep ' sysmon: ' > work/sysmon-linux-1.log
python3 ~/DFIR/scripts/sysmon_linux_view.py work/sysmon-linux-1.log
```

```
  1 ProcessCreate      RuleName=lab-cmd | Image=/usr/bin/curl | CommandLine=curl -s -o /tmp/day16/stage.sh http://127.0.0.1:8016/stage.sh
  3 NetworkConnect     RuleName=lab-net | Image=/usr/bin/curl | Protocol=tcp | Initiated=true | DestinationIp=127.0.0.1 | DestinationPort=8016
 11 FileCreate         RuleName=lab-drop | Image=/usr/bin/curl | TargetFilename=/tmp/day16/stage.sh
  1 ProcessCreate      RuleName=lab-cmd | Image=/usr/bin/bash | CommandLine=bash /tmp/day16/stage.sh
 11 FileCreate         RuleName=lab-drop | Image=/usr/bin/bash | TargetFilename=/tmp/day16/flag.txt
```

Five events, one line each: the `curl` process, its connection to 127.0.0.1:8016 (kept because **both** AND conditions matched), the file it wrote, the script running, and the file the script dropped. Each line carries the **RuleName** of the rule that kept it. The web server, `sleep` and everything else you ran weren't logged: the configuration didn't ask for them. (There's no `ParentImage` here: your shell was started before Sysmon, and Sysmon for Linux left its details empty. Processes started after Sysmon, like `sudo` in the next step, do get them; in a terminal opened after installing Sysmon you'd see `ParentImage=/usr/bin/bash`.)

Next, change the configuration while Sysmon runs, as an administrator (or an attacker) would, and use the log to see it happen. Then hunt the captured Linux events with Zircolite's Linux ruleset, and uninstall:

```bash
sed 's#<ProcessTerminate onmatch="include"/>#<ProcessTerminate onmatch="include"><Image name="lab-end" condition="end with">/curl</Image></ProcessTerminate>#' \
    work/day16-linux.xml > work/day16-linux-v2.xml
start=$(sudo wc -l < /var/log/syslog)
sudo sysmon -c "$PWD/work/day16-linux-v2.xml" > /dev/null 2>&1
sleep 1
curl -s -o /tmp/day16/stage2.sh http://127.0.0.1:8016/stage.sh
sleep 2
sudo tail -n +$((start + 1)) /var/log/syslog | grep ' sysmon: ' > work/sysmon-linux-2.log
python3 ~/DFIR/scripts/sysmon_linux_view.py work/sysmon-linux-2.log | sed "s#$HOME#~#g"
sha256sum work/day16-linux-v2.xml | cut -c1-64
kill $srv
cat work/sysmon-linux-1.log work/sysmon-linux-2.log > work/sysmon-linux.log
zircolite -S --events work/sysmon-linux.log -r $ZR/rules_linux.json -o work/linux-detections.json -l work/zircolite.log -q > /dev/null 2>&1
python3 - work/linux-detections.json <<'EOF'
import json, sys
for r in sorted(json.load(open(sys.argv[1])), key=lambda r: r["title"]):
    for m in r["matches"]:
        print(f'{r["rule_level"]:<8} {r["title"]} | EventID {m["EventID"]} | {m.get("Image")}')
EOF
sudo sysmon -u > /dev/null 2>&1
```

```
  1 ProcessCreate      RuleName=lab-cmd | Image=/usr/bin/sudo | CommandLine=sudo sysmon -c ~/cases/LAB-016/work/day16-linux-v2.xml
  1 ProcessCreate      RuleName=lab-cmd | Image=/usr/bin/sysmon | CommandLine=sysmon -c ~/cases/LAB-016/work/day16-linux-v2.xml | ParentImage=/usr/bin/sudo
 16 ConfigChange       Configuration=~/cases/LAB-016/work/day16-linux-v2.xml | ConfigurationFileHash=SHA256=43b2c7a750a8c2c8075c70b42d7fa763a46d2761c519a1674ffa543e235bd2bb
  1 ProcessCreate      RuleName=lab-cmd | Image=/usr/bin/curl | CommandLine=curl -s -o /tmp/day16/stage2.sh http://127.0.0.1:8016/stage.sh
  3 NetworkConnect     RuleName=lab-net | Image=/usr/bin/curl | Protocol=tcp | Initiated=true | DestinationIp=127.0.0.1 | DestinationPort=8016
 11 FileCreate         RuleName=lab-drop | Image=/usr/bin/curl | TargetFilename=/tmp/day16/stage2.sh
  5 ProcessTerminate   RuleName=lab-end | Image=/usr/bin/curl
43b2c7a750a8c2c8075c70b42d7fa763a46d2761c519a1674ffa543e235bd2bb
low      Curl Usage on Linux | EventID 1 | /usr/bin/curl
low      Curl Usage on Linux | EventID 3 | /usr/bin/curl
low      Curl Usage on Linux | EventID 11 | /usr/bin/curl
low      Curl Usage on Linux | EventID 1 | /usr/bin/curl
low      Curl Usage on Linux | EventID 3 | /usr/bin/curl
low      Curl Usage on Linux | EventID 11 | /usr/bin/curl
low      Curl Usage on Linux | EventID 5 | /usr/bin/curl
critical Linux Reverse Shell Indicator | EventID 1 | /usr/bin/bash
critical Linux Reverse Shell Indicator | EventID 11 | /usr/bin/bash
```

- **Event 16** recorded the new configuration's path and SHA-256, which matches `sha256sum`: on a real case, compare it with the hash of the configuration your IT team *thinks* is deployed. The new rule kept a **process terminated** event (5) for `curl`. `sudo` and `sysmon` themselves were logged because their command lines contain `day16`; `sysmon` does have a `ParentImage` (`sudo` started after Sysmon).
- Zircolite flagged `curl` (low) and, at **critical**, a "Linux Reverse Shell Indicator" on `bash`. Look at the **EventID**: that rule is about network connections (`bash` connecting anywhere but localhost), but Zircolite's Linux ruleset has no EventID conditions, so it matched `bash`'s **process** (1) and **file** (11) events, which have no `DestinationIp` at all. This is Day 15's logsource lesson again: always check that a match is the kind of event the rule was written for.

On a VM with systemd, `sysmon -i` starts the service and `sysmon -u` stops and removes it. (This lab was validated in a container without systemd, where the service binary was started by hand and the kernel tracing filesystem had to be mounted first; the events were identical.)

### Lab 2: Read a Sysmon configuration before you trust its log (20 min)

WS-ALICE ran SwiftOnSecurity's `sysmonconfig-export.xml`. Before reading its log, find out what that configuration keeps. `sysmon_config_summary.py` (in `scripts/`) counts each event type's include and exclude rules and says what they mean:

```bash
curl -sSfL -o work/sysmonconfig-export.xml https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/1836897f12fbd6a0a473665ef6abc34a6b497e31/sysmonconfig-export.xml
sha256sum work/sysmonconfig-export.xml | cut -c1-16
python3 ~/DFIR/scripts/sysmon_config_summary.py work/sysmonconfig-export.xml
python3 ~/DFIR/scripts/sysmon_config_summary.py work/sysmonconfig-export.xml --show FileCreateTime
python3 ~/DFIR/scripts/sysmon_config_summary.py work/sysmonconfig-export.xml --show PipeEvent | cut -c1-100
python3 ~/DFIR/scripts/sysmon_config_summary.py work/sysmonconfig-export.xml --show NetworkConnect | grep -E 'Usermode|"powershell.exe"'
```

```
055febc600e6d744
schemaversion 4.50
HashAlgorithms   md5,sha256,IMPHASH
CheckRevocation  (present, no value)

Filter tag             include exclude  meaning
ProcessCreate                -     138  everything except the exclude rules
FileCreateTime               3       9  only include matches, minus exclude matches
NetworkConnect              84       9  only include matches, minus exclude matches
ProcessTerminate             2       0  only events matching an include rule
DriverLoad                   -       3  everything except the exclude rules
ImageLoad                    0       -  nothing (empty include)
CreateRemoteThread           -       9  everything except the exclude rules
RawAccessRead                0       -  nothing (empty include)
ProcessAccess                0       -  nothing (empty include)
FileCreate                  53      11  only include matches, minus exclude matches
RegistryEvent              114      52  only include matches, minus exclude matches
FileCreateStreamHash        19       0  only events matching an include rule
PipeEvent                    9       -  only events matching an include rule
WmiEvent                     -       0  everything (empty exclude)
DnsQuery                     -     209  everything except the exclude rules

not mentioned (Sysmon default): FileDelete, ClipboardChange, ProcessTampering, FileDeleteDetected, FileBlockExecutable, FileBlockShredding, FileExecutableDetected
FileCreateTime onmatch=include (rules combined with OR)
    [T1099] Image begin with "C:\Users"
    [T1099] TargetFilename end with ".exe"
    [T1099] Image begin with "\Device\HarddiskVolumeShadowCopy"
FileCreateTime onmatch=exclude (rules combined with OR)
    Image image "OneDrive.exe"
    Image image "C:\Windows\system32\backgroundTaskHost.exe"
    Image contains "setup"
    Image contains "install"
    Image contains "Update\"
    Image end with "redist.exe"
    Image is "msiexec.exe"
    Image is "TrustedInstaller.exe"
    TargetFilename contains "\NVIDIA\NvBackend\ApplicationOntology\"
PipeEvent onmatch=include (rules combined with OR)
    PipeName contains any "paexec;remcom;csexec"
    PipeName contains any "\lsadump;\cachedump;\wceservicepipe"
    PipeName contains any "\isapi_http;\isapi_dg;\isapi_dg2;\sdlrpc;\ahexec;\winsession;\lsassw;\46a
    PipeName contains any "\atctl;\userpipe;\iehelper;\sdlrpc;\comnap"
    PipeName contains all "MSSE-;-server"
    PipeName begin with "\postex_"
    PipeName begin with "\postex_ssh_"
    PipeName begin with "\status_"
    PipeName begin with "\msagent_"
    [Usermode] Image begin with "C:\Users"
    Image image "powershell.exe"
```

Now predict, before you look at the log:

- **Process creation** (exclude list): every attacker process is logged.
- **Timestomping** (FileCreateTime): only when the **image** is under `C:\Users` or the **target** ends in `.exe`. alice used `powershell.exe` (in `System32`) on `payload.ps1` and on `svchost.tmp`, which she renamed to `.exe` only afterwards. **Not logged.**
- **Named pipes**: only PAExec, RemCom, CSExec and some malware and Cobalt Strike names. PsExec's `\PSEXESVC` pipes: **not logged**.
- **Network**: `powershell.exe` is in the include list (its download on 09-28 will be there), and so is anything run from `C:\Users` ("Usermode"): rclone in `AppData\Local\Temp\rc` will be logged.
- **Image load, raw disk access, process access**: empty includes, nothing logged. (A tool reading LSASS memory would leave no event 10 with this config.)

### Lab 3: WS-ALICE's Sysmon log (30 min)

`mk_sysmon_log.py` (in `scripts/`) writes WS-ALICE's Sysmon log with the events that configuration would have kept for the case. Like the Day 14 logs, it contains only the case's events. Print it as a timeline:

```bash
python3 ~/DFIR/scripts/mk_sysmon_log.py evidence/WS-ALICE
L=evidence/WS-ALICE/Windows/System32/winevt/Logs
~/tools/zircolite-venv/bin/python - "$L/Microsoft-Windows-Sysmon%4Operational.evtx" <<'EOF'
import json, sys
from evtx import PyEvtxParser
name = lambda p: p.rsplit("\\", 1)[-1]
for r in PyEvtxParser(sys.argv[1]).records_json():
    e = json.loads(r["data"])["Event"]
    eid, d = e["System"]["EventID"], e["EventData"]
    who = f'{name(d.get("Image", ""))}({d.get("ProcessId")})'
    if eid == 1:
        who = f'{name(d["ParentImage"])}({d["ParentProcessId"]}) -> {who} {d["User"].split(chr(92))[-1]}'
        what = d["CommandLine"]
    elif eid == 3:
        what = f'{d["Protocol"]} {d["SourceIp"]}:{d["SourcePort"]} -> {d["DestinationIp"]}:{d["DestinationPort"]} [{d["RuleName"]}]'
    elif eid == 22:
        what = f'{d["QueryName"]} = {d["QueryResults"]}'
    elif eid in (11, 15):
        what = f'{d["TargetFilename"]} [{d["RuleName"]}]'
    elif eid == 13:
        what = f'{d["TargetObject"].replace("HKU" + chr(92) + "S-1-5-21-3623811015-3361044348-30300820-1001", "HKU" + chr(92) + "<alice>")} = {d["Details"]}'
    else:
        what = ""
    print(f'{d["UtcTime"][:19]} {eid:>2}  {who}  {what}'[:150].rstrip())
EOF
```

```
  69632   27 events  Microsoft-Windows-Sysmon%4Operational.evtx
2026-09-28 10:13:41  1  explorer.exe(5012) -> powershell.exe(7816) alice  "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
2026-09-28 10:13:44 22  powershell.exe(7816)  downloads.example.net = ::ffff:198.51.100.23;
2026-09-28 10:13:44  3  powershell.exe(7816)  tcp 10.20.30.21:51344 -> 198.51.100.23:443 [-]
2026-09-28 10:14:22 11  powershell.exe(7816)  C:\Users\alice\AppData\Local\Temp\rc\rclone.exe [EXE]
2026-09-29 01:02:03 11  msedge.exe(6420)  C:\Users\alice\Downloads\payload.ps1 [Downloads]
2026-09-29 01:02:03 15  msedge.exe(6420)  C:\Users\alice\Downloads\payload.ps1:Zone.Identifier [-]
2026-09-29 01:05:11 11  System(4)  C:\Windows\PSEXESVC.exe [EXE]
2026-09-29 01:05:12 13  services.exe(680)  HKLM\System\CurrentControlSet\Services\PSEXESVC\Start = DWORD (0x00000003)
2026-09-29 01:05:12  1  services.exe(680) -> PSEXESVC.exe(7036) SYSTEM  C:\Windows\PSEXESVC.exe
2026-09-29 01:05:14  1  PSEXESVC.exe(7036) -> cmd.exe(9064) bob  "cmd"
2026-09-29 01:05:20  1  cmd.exe(9064) -> whoami.exe(3664) bob  whoami  /all
2026-09-29 01:05:44  1  cmd.exe(9064) -> net.exe(11568) bob  net  localgroup administrators
2026-09-29 01:09:31  1  explorer.exe(5576) -> powershell.exe(12052) alice  "powershell.exe" -w hidden -nop
2026-09-29 01:12:47  1  powershell.exe(12052) -> rclone.exe(11104) alice  "C:\Users\alice\AppData\Local\Temp\rc\rclone.exe" copy C:\Users\alice\Docume
2026-09-29 01:12:48 22  rclone.exe(11104)  g.api.mega.co.nz = ::ffff:198.51.100.77;
2026-09-29 01:12:48  3  rclone.exe(11104)  tcp 10.20.30.21:52817 -> 198.51.100.77:443 [Usermode]
2026-09-29 01:15:38  5  rclone.exe(11104)
2026-09-29 01:21:05  1  powershell.exe(12052) -> schtasks.exe(11404) alice  "C:\Windows\system32\schtasks.exe" /create /tn OneDriveUpdate /xml C:\User
2026-09-29 01:21:05 11  svchost.exe(1540)  C:\Windows\System32\Tasks\OneDriveUpdate [T1053]
2026-09-29 01:21:29 13  powershell.exe(12052)  HKU\<alice>\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OneDriveUpdate = C:\Users\alice\AppData\Local
2026-09-29 01:22:10  1  powershell.exe(12052) -> sc.exe(8016) alice  "C:\Windows\system32\sc.exe" create OneDriveSync binPath= "C:\Users\alice\AppData
2026-09-29 01:22:10 13  services.exe(680)  HKLM\System\CurrentControlSet\Services\OneDriveSync\Start = DWORD (0x00000002)
2026-09-29 01:22:11  1  powershell.exe(12052) -> sc.exe(9328) alice  "C:\Windows\system32\sc.exe" start OneDriveSync
2026-09-29 01:22:11  1  services.exe(680) -> rclone.exe(3884) SYSTEM  C:\Users\alice\AppData\Local\Temp\rc\rclone.exe copy C:\Users\alice\Documents re
2026-09-29 01:22:11  5  rclone.exe(3884)
2026-09-29 07:58:21  1  services.exe(680) -> rclone.exe(2900) SYSTEM  C:\Users\alice\AppData\Local\Temp\rc\rclone.exe copy C:\Users\alice\Documents re
2026-09-29 07:58:21  5  rclone.exe(2900)
```

What Sysmon adds to Days 9–15, line by line:

- **09-28 10:13:44**: the "download" in PowerShell's 4104 now has a **DNS answer** (`downloads.example.net` = 198.51.100.23) and a **connection** to it on 443. At 10:14:22 PowerShell **wrote `rclone.exe`** into `Temp\rc` (kept by the `EXE` rule): `Expand-Archive`.
- **01:02:03**: Edge saved `payload.ps1` in Downloads, and event **15** records its `Zone.Identifier`: the same mark of the web you parsed from the MFT on Day 10.
- **01:05:11–01:05:44**: the PsExec chain as a tree: `System` writes `PSEXESVC.exe`, `services.exe` sets its service `Start` value and starts it, `PSEXESVC.exe` starts `cmd` **as bob**, and `cmd` runs `whoami` and `net`.
- **01:12:47–01:15:38**: rclone resolves **`g.api.mega.co.nz`** and connects to it on 443 (RuleName `Usermode`), then **exits at 01:15:38**: the exfiltration's destination and duration, which no Day 14 log had. (The addresses here are documentation ranges standing in for real ones.)
- **01:21–01:22**: persistence three ways: the task file in `System32\Tasks` (by the Schedule service's `svchost.exe`), the **Run key** value (event 13, RuleName `T1060,RunKey`) and the **OneDriveSync** service's `Start` value.
- **01:22:11 and 07:58:21**: `services.exe` started rclone **as SYSTEM**, and each time it **exited within half a second with no DNS query or connection**. The service command line has no `--config`, so rclone running as SYSTEM most likely found no `remote:` to copy to: the persistence fired, after the reboot too, but this copy of it didn't exfiltrate. (Day 14's Security log, a hand-picked extract, skipped these two runs; Day 12's BAM entry for SYSTEM at 07:58:21 matches the second.)
- **What isn't here**: the 01:20:44 timestomping and the PsExec pipes, exactly as Lab 2 predicted. The configuration, not Sysmon, made those blind spots.

Now decode the GUIDs of the three rclone runs:

```bash
~/tools/zircolite-venv/bin/python - "$L/Microsoft-Windows-Sysmon%4Operational.evtx" <<'EOF'
import json, sys, datetime
from evtx import PyEvtxParser
def start(g):
    p = g.strip("{}").split("-")
    return datetime.datetime.fromtimestamp(int(p[2] + p[1], 16), datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
for r in PyEvtxParser(sys.argv[1]).records_json():
    e = json.loads(r["data"])["Event"]
    d = e["EventData"]
    if e["System"]["EventID"] == 1 and d["Image"].endswith("rclone.exe"):
        lg = d["LogonGuid"].split("-")
        print(f'{d["UtcTime"][:19]}  ProcessGuid {d["ProcessGuid"]} -> started {start(d["ProcessGuid"])}')
        print(f'      parent {d["ParentImage"]} started {start(d["ParentProcessGuid"])}')
        print(f'      LogonGuid ...{lg[3]}-{lg[4]} -> LogonId 0x{int.from_bytes(bytes.fromhex(lg[3] + lg[4]), "little"):x}'
              f' ({d["LogonId"]}), integrity {d["IntegrityLevel"]}')
        print(f'      {d["Hashes"][:80]}')
EOF
```

```
2026-09-29 01:12:47  ProcessGuid 7C41D2A9-108F-6ABB-D001-000000002E00 -> started 2026-09-29 01:12:47
      parent C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe started 2026-09-29 01:09:31
      LogonGuid ...F2A1-030000000000 -> LogonId 0x3a1f2 (0x3a1f2), integrity High
      MD5=2E76C51AB233B6F0D6458100AAD01183,SHA256=138B9134A1230B0D86DB24B766517A8BBEED
2026-09-29 01:22:11  ProcessGuid 7C41D2A9-12C3-6ABB-FF01-000000002E00 -> started 2026-09-29 01:22:11
      parent C:\Windows\System32\services.exe started 2026-09-29 00:57:05
      LogonGuid ...E703-000000000000 -> LogonId 0x3e7 (0x3e7), integrity System
      MD5=2E76C51AB233B6F0D6458100AAD01183,SHA256=138B9134A1230B0D86DB24B766517A8BBEED
2026-09-29 07:58:21  ProcessGuid 7C41D2A9-6F9D-6ABB-4200-000000002E00 -> started 2026-09-29 07:58:21
      parent C:\Windows\System32\services.exe started 2026-09-29 07:58:19
      LogonGuid ...E703-000000000000 -> LogonId 0x3e7 (0x3e7), integrity System
      MD5=2E76C51AB233B6F0D6458100AAD01183,SHA256=138B9134A1230B0D86DB24B766517A8BBEED
```

The ProcessGuid gives each process's start time, and the **parent's** GUID gives the parent's: the hidden PowerShell had been running since 01:09:31, while `services.exe` started at boot (00:57:05, then 07:58:19 after the reboot). The LogonGuid ends with the LogonId (alice's `0x3a1f2`, SYSTEM's `0x3e7`), linking the process to Day 14's logon events. All three runs have the **same hashes**: the same binary each time. (The hashes are of stand-in content, as on Day 12; don't look them up.)

### Lab 4: Convert and check rules with sigma-cli (20 min)

```bash
sigma list targets
sigma list pipelines | awk -F '|' 'NF > 5 { for (i = 2; i <= 4; i++) gsub(/^ +| +$/, "", $i);
    if ($2 != "Identifier") printf "%-27s %s\n", $2, $4 }'
RC=~/tools/sigma/rules/windows/process_creation/proc_creation_win_pua_rclone_execution.yml
sigma convert -t splunk -p sysmon -p splunk_windows $RC 2> /dev/null
sigma convert -t splunk -p windows-audit -p splunk_windows $RC 2> /dev/null
sigma convert -t sqlite -p sysmon $RC 2> /dev/null | cut -c1-150
```

```
+-------------+----------------------------------------+------------------------------+--------+
| Identifier  | Target Query Language                  | Processing Pipeline Required | Plugin |
+-------------+----------------------------------------+------------------------------+--------+
| splunk      | Splunk SPL & tstats data model queries | Yes                          | splunk |
| splunk_spl2 | Splunk SPL2 queries                    | Yes                          | splunk |
| sqlite      | SQLite backend                         | No                           | sqlite |
+-------------+----------------------------------------+------------------------------+--------+
splunk_windows              Splunk Windows log source conditions
splunk_sysmon_acceleration  Splunk Windows Sysmon search acceleration keywords
splunk_cim                  Splunk CIM Data Model Mapping
sysmon                      Generic Log Sources to Sysmon Transformation
windows-logsources          Add Channel condition for Windows log sources
windows-audit               Map generic log sources to Windows audit logs
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 (CommandLine="*--config *" CommandLine="*--no-check-certificate *" CommandLine="* copy *") OR (Image="*\\rclone.exe" OR Description="Rsync for cloud storage" CommandLine IN ("*pass*", "*user*", "*copy*", "*sync*", "*config*", "*lsd*", "*remote*", "*ls*", "*mega*", "*pcloud*", "*ftp*", "*ignore-existing*", "*auto-confirm*", "*transfers*", "*multi-thread-streams*", "*no-check-certificate *"))
source="WinEventLog:Security" EventCode=4688 (CommandLine="*--config *" CommandLine="*--no-check-certificate *" CommandLine="* copy *") OR (NewProcessName="*\\rclone.exe" OR Description="Rsync for cloud storage" CommandLine IN ("*pass*", "*user*", "*copy*", "*sync*", "*config*", "*lsd*", "*remote*", "*ls*", "*mega*", "*pcloud*", "*ftp*", "*ignore-existing*", "*auto-confirm*", "*transfers*", "*multi-thread-streams*", "*no-check-certificate *"))
SELECT * FROM logs WHERE EventID=1 AND ((CommandLine LIKE '%--config %' ESCAPE '\' AND CommandLine LIKE '%--no-check-certificate %' ESCAPE '\' AND Com
```

The same SigmaHQ rule becomes three queries. With the **`sysmon`** pipeline it asks Splunk for Sysmon event 1 and `Image`; with **`windows-audit`** it asks for Security **4688** and `NewProcessName`; with the **SQLite** back-end it becomes the SQL Zircolite runs. That's the fix for Day 15's Chainsaw gap, and the reason your SIEM query must match how its logs are collected.

Lab 3 showed a pattern worth a rule: a service starting a program from a user's Temp folder. Write it quickly, let `sigma check` review it, fix what it finds, and convert it for both log sources:

```bash
cat > rules/draft.yml <<'EOF'
title: Service Runs A Program From A User Temp Folder
status: experimental
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage|endswith: '\services.exe'
        Image|contains: '\AppData\Local\Temp\'
    condition: selection
EOF
sigma check -x attacktag -x d3_fendtag rules/draft.yml 2> /dev/null | grep -E -o '^Found.*|[A-Za-z]+Issue' | sort -u
cat > rules/proc_creation_win_services_child_in_user_temp.yml <<'EOF'
title: Service Runs A Program From A User Temp Folder
id: 3e8c1f52-7a4d-4b9e-a0c6-5d2f8e91b7a4
status: experimental
description: |
    Detects a process started by the Service Control Manager (services.exe) whose image sits in a
    user's Temp folder. Services normally run from Program Files or System32; a service binary in
    AppData\Local\Temp is a common persistence trick.
references:
    - https://github.com/Mr-Phoenix07/DFIR
author: DFIR Daily (Day 16)
date: 2026-10-13
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1543.003
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage|endswith: '\services.exe'
        Image|contains: '\AppData\Local\Temp\'
    condition: selection
falsepositives:
    - Installers that register a temporary service while they run
level: high
EOF
rm rules/draft.yml
sigma check -x attacktag -x d3_fendtag rules/ 2> /dev/null | tail -n 3
sigma convert -t splunk -p sysmon -p splunk_windows rules/ 2> /dev/null
sigma convert -t splunk -p windows-audit -p splunk_windows rules/ 2> /dev/null
```

```
FilenameLengthIssue
Found 0 errors, 0 condition errors and 2 issues.
IdentifierExistenceIssue
No rule errors found.
No condition errors found.
No validation issues found.
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 ParentImage="*\\services.exe" Image="*\\AppData\\Local\\Temp\\*"
source="WinEventLog:Security" EventCode=4688 ParentProcessName="*\\services.exe" NewProcessName="*\\AppData\\Local\\Temp\\*"
```

The draft had no `id` and a file name that doesn't follow SigmaHQ's naming convention (`proc_creation_win_...`); the finished rule passes. `-x attacktag -x d3_fendtag` skips the validators that download MITRE ATT&CK and D3FEND data from GitHub; on a connected machine you can leave them in. The finished rule converts for Sysmon and for 4688 alike.

### Lab 5: Hunt with Zircolite (25 min)

First, Zircolite's ready-made Sysmon ruleset (SigmaHQ rules converted by the Zircolite project, 2,826 rules in v4.5.0) on WS-ALICE's Sysmon log, then your new rule as native YAML through the `sysmon` pipeline:

```bash
summary() {
python3 - "$@" <<'EOF'
import json, sys
order = ["critical", "high", "medium", "low", "informational"]
for path in sys.argv[1:]:
    hits = json.load(open(path))
    print(f"{path}: {sum(r['count'] for r in hits)} matches, {len(hits)} rules")
    for r in sorted(hits, key=lambda r: (order.index(r["rule_level"]), -r["count"], r["title"],
                                         sorted({m["OriginalLogfile"] for m in r["matches"]}))):
        files = sorted({m["OriginalLogfile"] for m in r["matches"]})
        many = len({m["OriginalLogfile"] for r in hits for m in r["matches"]}) > 1
        print(f'  {r["rule_level"]:<13} {r["count"]:>3}  {r["title"]}' + (f'  [{", ".join(files)}]' if many else ""))
EOF
}
zircolite --events $L -s Sysmon -r $ZR/rules_windows_sysmon.json -o work/alice-sysmon.json -l work/zircolite.log -q > /dev/null 2>&1
summary work/alice-sysmon.json
zircolite --events $L -s Sysmon -r rules/ -p sysmon -p windows-logsources -o work/alice-custom.json -l work/zircolite.log -q > /dev/null 2>&1
python3 -c 'import json, sys; [print(m["UtcTime"][:19], m["User"], m["ParentImage"], "->", m["Image"]) for r in json.load(open(sys.argv[1])) for m in r["matches"]]' work/alice-custom.json
```

```
work/alice-sysmon.json: 20 matches, 18 rules
  high            3  PUA - Rclone Execution
  high            1  New RUN Key Pointing to Suspicious Folder
  high            1  Suspicious New Service Creation
  high            1  Unusual File Download from Direct IP Address
  high            1  Windows Shell/Scripting Processes Spawning Suspicious Programs
  medium          1  CurrentVersion Autorun Keys Modification
  medium          1  Enumerate All Information With Whoami.EXE
  medium          1  Potentially Suspicious PowerShell Child Processes
  medium          1  PsExec Service Execution
  medium          1  Schedule Task Creation From Env Variable Or Potentially Suspicious Path Via Schtasks.EXE
  medium          1  Suspicious Group And Account Reconnaissance Activity Using Net.EXE
  low             1  Local Accounts Discovery
  low             1  Net.EXE Execution
  low             1  Network Connection Initiated By PowerShell Process
  low             1  New Service Creation Using Sc.EXE
  low             1  PsExec Service File Creation
  low             1  Scheduled Task Created - FileCreation
  low             1  Scheduled Task Creation Via Schtasks.EXE
2026-09-29 01:22:11 NT AUTHORITY\SYSTEM C:\Windows\System32\services.exe -> C:\Users\alice\AppData\Local\Temp\rc\rclone.exe
2026-09-29 07:58:21 NT AUTHORITY\SYSTEM C:\Windows\System32\services.exe -> C:\Users\alice\AppData\Local\Temp\rc\rclone.exe
```

18 rules matched. Compare with Day 15: the same process rules fire (rclone, whoami, net, schtasks, sc), but now Sysmon also gives you detections Day 15 couldn't make: **"New RUN Key Pointing to Suspicious Folder"** (high), **"Unusual File Download from Direct IP Address"** (high, from the `Zone.Identifier` stream), **"PsExec Service File Creation"**, **"Scheduled Task Created - FileCreation"**, PowerShell's network connection, and **"PUA - Rclone Execution" three times**: the two SYSTEM runs included. Your rule found exactly those two service runs.

Now the Day 14 Security log (4688 only, no Sysmon) with the native SigmaHQ `process_creation` rules, once through the `sysmon` pipeline and once through `windows-audit`:

```bash
python3 ~/DFIR/scripts/mk_event_logs.py evidence/WS-ALICE > /dev/null
for p in sysmon windows-audit; do
  zircolite --events $L/Security.evtx -r ~/tools/sigma/rules/windows/process_creation -p $p -p windows-logsources \
            -o work/security-$p.json -l work/zircolite.log -q > /dev/null 2>&1
  python3 -c 'import json, sys; h = json.load(open(sys.argv[1])); print(sys.argv[2], "pipeline:", len(h), "rules matched"); [print("   ", r["rule_level"], "|", r["title"]) for r in sorted(h, key=lambda r: r["title"])]' work/security-$p.json $p
done
```

```
sysmon pipeline: 0 rules matched
windows-audit pipeline: 10 rules matched
    medium | Enumerate All Information With Whoami.EXE
    low | Local Accounts Discovery
    low | New Service Creation Using Sc.EXE
    high | PUA - Rclone Execution
    medium | PsExec Service Execution
    medium | Schedule Task Creation From Env Variable Or Potentially Suspicious Path Via Schtasks.EXE
    low | Scheduled Task Creation Via Schtasks.EXE
    medium | Suspicious Group And Account Reconnaissance Activity Using Net.EXE
    high | Suspicious New Service Creation
    high | Windows Shell/Scripting Processes Spawning Suspicious Programs
```

Same rules, same log: **0** with the wrong pipeline, **10** with the right one. With `windows-audit`, the rules that Chainsaw couldn't run against 4688 on Day 15 (rclone, whoami, net, schtasks, sc, PsExec) all match.

Finally, two **real** Sysmon logs from DeepBlueCLI's samples: a Metasploit and a Sliver attack on the same test machine:

```bash
cd ~/cases/LAB-016/samples
for f in metasploit-sysmon.evtx sliver-sysmon.evtx; do
  curl -sSfL -o $f https://raw.githubusercontent.com/sans-blue-team/DeepBlueCLI/master/evtx/$f
done
sha256sum *.evtx | cut -c1-16,65- | tee ../notes/samples.sha256
cd ~/cases/LAB-016
zircolite --events samples -r $ZR/rules_windows_sysmon.json -o work/samples-sysmon.json -l work/zircolite.log -q > /dev/null 2>&1
summary work/samples-sysmon.json
```

```
acacf7bc456ff9b8  metasploit-sysmon.evtx
9c6b2ca0c7bcefe9  sliver-sysmon.evtx
work/samples-sysmon.json: 110 matches, 27 rules
  high           10  HackTool - CrackMapExec Execution Patterns  [metasploit-sysmon.evtx]
  high           10  HackTool - Potential Impacket Lateral Movement Activity  [metasploit-sysmon.evtx]
  high           10  Hermetic Wiper TG Process Patterns  [metasploit-sysmon.evtx]
  high           10  Suspicious Redirection to Local Admin Share  [metasploit-sysmon.evtx]
  high            5  Suspicious Eventlog Clearing or Configuration Change Activity  [metasploit-sysmon.evtx]
  high            5  Suspicious Eventlog Clearing or Configuration Change Activity  [sliver-sysmon.evtx]
  high            3  HackTool - CrackMapExec Execution Patterns  [sliver-sysmon.evtx]
  high            3  HackTool - Potential Impacket Lateral Movement Activity  [sliver-sysmon.evtx]
  high            3  Hermetic Wiper TG Process Patterns  [sliver-sysmon.evtx]
  high            3  Suspicious Redirection to Local Admin Share  [sliver-sysmon.evtx]
  high            2  Abused Debug Privilege by Arbitrary Parent Processes  [metasploit-sysmon.evtx]
  high            1  Potential Meterpreter/CobaltStrike Activity  [metasploit-sysmon.evtx]
  high            1  Privilege Escalation via Named Pipe Impersonation  [metasploit-sysmon.evtx]
  high            1  Rare Remote Thread Creation By Uncommon Source Image  [sliver-sysmon.evtx]
  high            1  Sysmon Blocked Executable  [metasploit-sysmon.evtx]
  medium         10  WmiPrvSE Spawned A Process  [metasploit-sysmon.evtx]
  medium          6  Elevated System Shell Spawned  [metasploit-sysmon.evtx]
  medium          3  WmiPrvSE Spawned A Process  [sliver-sysmon.evtx]
  medium          2  Uncommon GrantedAccess Flags On LSASS  [metasploit-sysmon.evtx]
  medium          1  Potential Shellcode Injection  [metasploit-sysmon.evtx]
  medium          1  Potentially Suspicious GrantedAccess Flags On LSASS  [metasploit-sysmon.evtx]
  medium          1  Recon Command Output Piped To Findstr.EXE  [metasploit-sysmon.evtx]
  medium          1  Remote Thread Creation In Uncommon Target Image  [sliver-sysmon.evtx]
  low            11  CMD Shell Output Redirect  [metasploit-sysmon.evtx]
  low             3  CMD Shell Output Redirect  [sliver-sysmon.evtx]
  low             1  Potential Executable Run Itself As Sacrificial Process  [sliver-sysmon.evtx]
  informational   2  Suspicious Tasklist Discovery Command  [metasploit-sysmon.evtx]
```

Read them like an analyst, not like a list:

- **Lateral movement by WMI**: `WmiPrvSE.exe` spawning `cmd.exe /Q /c ... 1> \\127.0.0.1\ADMIN$\__<timestamp> 2>&1` is the signature of Impacket's `wmiexec` (and CrackMapExec, which uses it). Four "high" rules describe that **one** pattern, ten times in one log and three in the other.
- **"Hermetic Wiper TG Process Patterns"**: the same command pattern also matches a rule written for the HermeticWiper attacks. There's no wiper here. Right pattern, wrong story: Day 15's mislabel again.
- **Anti-forensics**: both attacks begin by clearing the Security, System, Application, Sysmon and Defender logs with `wevtutil cl` ("Suspicious Eventlog Clearing", 5 each). On a real case, a copy forwarded to a SIEM is what survives that.
- **Metasploit**: a `getsystem` named-pipe service, LSASS opened with credential-reading access rights, a remote thread into LSASS and `winlogon`, an elevated SYSTEM shell, and "Sysmon Blocked Executable" (event 27: Sysmon's FileBlockExecutable stopped `hello.exe` in `Music`, and the attacker simply copied it to `C:\`).
- **Sliver**: a remote thread from the implant (`JOINT_BALL.exe`) into `spoolsv.exe`, then from `spoolsv.exe` into `winlogon.exe` ("Rare Remote Thread Creation", "Remote Thread Creation In Uncommon Target Image"): migration between processes.

---

## ✅ Knowledge check

1. Name three questions about WS-ALICE that default Windows logging couldn't answer and Sysmon could.
2. On a machine you're investigating, how do you find out whether process creation auditing, command lines and Script Block Logging were enabled?
3. In a Sysmon configuration, what does `<ProcessTerminate onmatch="include"/>` do? And `<WmiEvent onmatch="exclude"/>`?
4. Why didn't WS-ALICE's Sysmon log show the timestomping, and what config change would have caught it?
5. What can you learn from a ProcessGuid without looking at any other event?
6. Event 16 shows a configuration hash that doesn't match the configuration IT deployed. What do you do?
7. The same Sigma rule found 0 events with one pipeline and 10 with another, on the same log. Why?
8. A critical "reverse shell" detection points at a file-creation event. What went wrong, and how should you handle such detections?

<details>
<summary><b>Answers</b></summary>

1. Any three of: where rclone connected (DNS name and IP, event 22/3); how long it ran (event 5); which binary ran (hashes, OriginalFileName); that `PSEXESVC.exe` was written by `System` just before the service started (event 11); the Run key's value (13); where `payload.ps1` came from (event 15's `Zone.Identifier`); that the service ran rclone as SYSTEM after the reboot but made no connection.
2. Live: `auditpol /get /category:*`, `wevtutil gl` for sizes, and the policy registry values. Dead box: the SOFTWARE hive's `...\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled` and `SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`; the advanced audit policy in the SECURITY hive (`Policy\PolAdtEv`); and, most practically, which event IDs and fields the logs actually contain, and from when.
3. An `include` with no rules matches nothing, so no process-terminated events are logged. An `exclude` with no rules excludes nothing, so all WMI events are logged.
4. SwiftOnSecurity's `FileCreateTime` rules only keep changes made by programs under `C:\Users` or to files ending in `.exe`; alice used `powershell.exe` from `System32` on `.ps1` and `.tmp` files. Including events from script hosts (e.g. `Image` with `condition="image"` for `powershell.exe`), or logging all `FileCreateTime` events and excluding known noisy installers, would have caught it.
5. In real Sysmon logs, the second and third groups encode the process **start time** (Unix seconds); the first group is the same for every process on a machine. A LogonGuid also ends with the **LogonId**. So one child event's `ParentProcessGuid` tells you when the parent started, even if the parent's own event 1 is long gone.
6. Treat it as possible tampering: find when it changed (event 16's time; events 4 and 255 around it; the System log for the Sysmon service), get the configuration that was loaded (`sysmon -c` on the live host, or the registry), compare it with the approved one, and assume the blind spots it created were used. It can also be an unannounced change by IT, so ask.
7. Pipelines map a generic rule to a log source. The `sysmon` pipeline made the rules look for Sysmon event 1 in the Sysmon channel with `Image`, which a Security log doesn't have; `windows-audit` made them look for 4688 with `NewProcessName`.
8. The ruleset had no EventID condition, so a network-connection rule ran against every event type, and fields missing from file and process events made its "not localhost" test pass. Check each match's EventID and fields against the rule's `logsource`; prefer rulesets and pipelines that add EventID conditions; report such rules as false positives.

</details>

---

## 📚 Further reading

- Microsoft Sysinternals, *Sysmon* documentation (event IDs, configuration entries and filtering) and the `sysmon -s` schema
- Microsoft, *SysmonForLinux* README and INSTALL guide (https://github.com/microsoft/SysmonForLinux)
- SwiftOnSecurity, *sysmon-config*; Olaf Hartong, *sysmon-modular* (configs, and how they are built and validated)
- Microsoft, *Command line process auditing* and *about_Logging_Windows* (PowerShell Script Block, Module and Transcription logging)
- SigmaHQ, *sigma-cli* README and the pySigma documentation on processing pipelines (https://sigmahq-pysigma.readthedocs.io/)
- wagga40, *Zircolite* documentation (https://wagga40.github.io/Zircolite/): Usage, Advanced, and the Viewer

---

## ⏭️ Tomorrow: Day 17

**SRUM, Recycle Bin & Windows Timeline (ActivitiesCache).** Tools: **SrumECmd**, **RBCmd**, **WxTCmd**.
Today's logs showed rclone running for three minutes. Tomorrow's artifacts can say how many bytes it sent, which files were deleted and when, and what alice was doing in each application.

---

<sub>Part of the <a href="../README.md">DFIR Daily</a> series · <a href="../CURRICULUM.md">Full 60-day curriculum</a> · For educational and authorised use only.</sub>
