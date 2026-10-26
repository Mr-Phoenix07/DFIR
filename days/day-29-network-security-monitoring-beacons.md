# Day 29: Network Security Monitoring — Logs, Alerts & Beacon Detection

> **Phase 4: Network Forensics** · **Level:** 🔴 Advanced · **Time:** ~4 hours (reading + labs) · **Posted:** 2026-10-26
>
> **Tools today:** 🛠️ Zeek · 🛠️ Suricata · 🛠️ RITA

---

## 🎯 Learning objectives

By the end of today you will be able to:

1. Distinguish the three NSM layers — **signature IDS** (Suricata), **protocol logging** (Zeek), and **behavioural analytics** (RITA) — and what each catches.
2. Run **Suricata** over a capture to raise signature alerts *and* log a flow record for every connection.
3. Read what Zeek produces (`conn.log`, `dns.log`, `http.log`, …) and why those logs feed detection at scale.
4. Explain **beaconing** and detect it by **connection cadence** — many connections to one destination at a near-constant interval, low in jitter.
5. Weigh the limits: encryption, alert fatigue, base rates, and why a regular beat is a *lead*, not a verdict.

---

## Part 1: The lesson

Day 28 read individual packets. Network Security Monitoring (NSM) is the discipline of doing that **continuously and at scale** — not to stare at packets, but to turn traffic into **evidence and detections** you can keep and query. Three complementary approaches, and you want all three.

### 1.1 Signatures, logs, and behaviour

- **Signature IDS/IPS — Suricata.** Matches traffic against rules ("this byte pattern / this URI / this JA3 is known-bad") and raises **alerts**. Great for *known* threats (Emerging Threats, Talos rule sets); blind to novel ones, and noisy if untuned. As an **IPS** (inline) it can also block.
- **Protocol logging — Zeek.** Not primarily an alerter: Zeek watches traffic and writes **structured logs** of what happened — one `conn.log` row per connection (the 5-tuple, bytes, duration, state), plus `dns.log`, `http.log`, `ssl.log`, `files.log` and more. This is the raw material of hunting: you query logs, not packets, and you keep them for months.
- **Behavioural analytics — RITA.** Reads Zeek's `conn.log` and looks for **patterns no single packet shows**: beaconing (regular call-homes), long connections, rare FQDNs, data-exfil volumes. Statistics over the logs, not signatures.

Suricata logs flows too, and Zeek can alert — the categories blur — but the mindset is the point: *match the known, log everything, analyse the rest.*

### 1.2 What Zeek logs give you

A single `conn.log` answers most triage questions without a packet in sight: who connected to whom (`id.orig_h` → `id.resp_h:resp_p`), for how long (`duration`), how much each way (`orig_bytes`/`resp_bytes`), how it ended (`conn_state`), and which service (`service`). `dns.log` ties names to IPs over time; `http.log` and `ssl.log` capture requests and TLS metadata (SNI, JA3) even when the payload is encrypted. These are compact, greppable, and keep long after the full PCAP has rolled off — which is why detection and hunting run on **logs**, with full packets kept only for a short window (Day 30 scales this up).

### 1.3 Beaconing, and how you detect it

Most C2 implants **call home on a schedule** — every 60 seconds, every hour — to ask for commands. Any one of those connections is unremarkable; the **pattern** is the tell:

- **Regular interval.** Connections to one destination separated by a near-constant time. Measured over many connections, the **jitter** (variation in the interval) is low. A good statistic is the **coefficient of variation** = stdev/mean of the inter-arrival times: a beacon's is small; human browsing is bursty and irregular (large, or too few connections to score).
- **Other signals** stack on top: a consistent small payload size, a rare/young destination FQDN, a long cumulative duration. RITA combines these into a score.
- **Jitter defeats the naive version.** Modern implants randomise the interval (±N%) and sleep, so detectors look at the *distribution*, not an exact period, and still catch a loose rhythm.

Today's lab makes this concrete: Suricata flags the known C2 IP and logs every flow; then a RITA-style analyzer measures the cadence to each destination and picks the beacon out of the noise.

### 1.4 Limits

- **Encryption.** You rarely read C2 payloads; detection leans on **metadata** — cadence, volume, TLS fingerprints, destination reputation.
- **Alert fatigue & base rates.** A signature that fires thousands of times a day trains analysts to ignore it; a beacon detector tuned too loose drowns you in legitimate polls (update checks, NTP, telemetry). Tune to your environment and **allow-list the known-regular**.
- **Evasion.** Domain fronting, fast flux, randomised jitter, and low-and-slow beacons all blunt detection; combine signals and keep the logs long enough to see slow patterns.
- **A beat is a lead.** Confirm the destination and rule out a legitimate scheduled task before you call a regular connection "C2".

Today's labs **run Suricata for real**; **Zeek** can't be installed here (its package repo is unreachable from this box) and **RITA** needs Zeek logs plus a datastore — both are documented, and the lab's `beacon_hunt.py` demonstrates RITA's core cadence analysis on the capture directly.

---

## Part 2: Tools

**Suricata** runs here (apt). **Zeek** isn't installable on this box (repo unreachable) and **RITA** needs Zeek logs + its datastore, so both are documented for a real deployment. `VER` is the version you fetch.

### 🛠️ Tool 1: Zeek

| | |
|---|---|
| **What** | A network-analysis framework (formerly Bro) that turns traffic into rich, structured protocol **logs** (and runs detection scripts). |
| **Why** | The de-facto source of network metadata for hunting and for tools like RITA: `conn.log` + per-protocol logs, live or from a PCAP. |

#### Requirements

- Linux/macOS; for live capture, an interface and privilege. Reading a PCAP needs neither.

#### Installation

```bash
# Official packages (per the Zeek docs) — add the Zeek OBS repo for your distro, then:
sudo apt install -y zeek            # Debian/Ubuntu (repo: software.opensuse.org // zeek)
sudo dnf install zeek               # Fedora/RHEL (Zeek repo)
brew install zeek                   # macOS
# Or Docker:  docker run --rm -v "$PWD:/pcap" zeek/zeek zeek -r /pcap/capture.pcap
# Docs/repo: https://docs.zeek.org  ·  https://github.com/zeek/zeek   (binary is under /opt/zeek/bin)
```

#### Configuration / first use

```bash
# Offline: generate logs from a capture into the current directory
zeek -r capture.pcap
ls   # conn.log dns.log http.log ssl.log files.log weird.log ...
# Read a log column-wise (tab-separated; zeek-cut selects fields):
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto service duration orig_bytes resp_bytes
# Live: configure node.cfg / local.zeek and run via zeekctl.
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| `zeek: command not found` | It installs under `/opt/zeek/bin`; add it to `PATH` (or use the full path). |
| No logs written | You lack write permission in the CWD, or the PCAP had no parseable traffic; check `weird.log`/`reporter.log`. |
| Logs are JSON vs TSV | Output format is configurable (`LogAscii::use_json`); `zeek-cut` expects the TSV form. |

### 🛠️ Tool 2: Suricata

| | |
|---|---|
| **What** | A high-performance IDS/IPS and NSM engine: signature alerts **plus** EVE JSON logs (flows, DNS, HTTP, TLS, files). |
| **Why** | Catches known threats with community rule sets and, like Zeek, logs every flow — one tool for both signature detection and metadata. |

#### Requirements

- Linux/*nix; for live/IPS, an interface and privilege. Reading a PCAP needs neither. Rule sets (Emerging Threats open / Talos).

#### Installation

```bash
sudo apt install -y suricata        # Debian/Ubuntu/SIFT (validated here: 7.0.x)
sudo dnf install suricata           # Fedora/RHEL
brew install suricata               # macOS
sudo suricata-update                # fetch the ET open rule set
# Docs: https://docs.suricata.io
```

#### Configuration / first use

```bash
# Offline over a capture, with a rules file, writing logs to ./out:
suricata -r capture.pcap -S rules/local.rules -l ./out --runmode single
ls out    # eve.json  fast.log  stats.log
# Live IDS on an interface (root):   suricata -i eth0 -l /var/log/suricata
# Inline IPS (NFQUEUE):              suricata -q 0
# eve.json is one JSON object per line: event_type alert|flow|dns|http|tls|...
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| No alerts | Rules not loaded/updated — run `suricata-update`, point `-S`/`-c` at the right rules; confirm with a known test rule. |
| Flooded with alerts | Tune/disable noisy SIDs, use thresholds, and baseline before enabling IPS. |
| "bad checksum" drops | Capturing host's checksum offload; add `-k none` to skip checksum validation on a capture. |
| Need per-protocol logs | They're in `eve.json` (`event_type`), not separate files; filter with `jq`/a parser. |

### 🛠️ Tool 3: RITA

| | |
|---|---|
| **What** | Real Intelligence Threat Analytics (Active Countermeasures): analyses **Zeek logs** to surface beacons, long connections, rare FQDNs and exfil. |
| **Why** | Turns a pile of `conn.log` rows into a ranked list of **beaconing** and anomalous destinations — the behavioural layer on top of Zeek. |

#### Requirements

- Linux; **Zeek logs** as input. Install/runtime requirements vary by version (older RITA needs **MongoDB**; recent releases are more self-contained) — follow the version's README.

#### Installation

```text
Download a release (version VER) from https://github.com/activecm/rita/releases, or build with Go.
Check your version's README for its datastore requirement (older versions require MongoDB) before
running. Active Countermeasures also ships "AC-Hunter" and an install script for a full deployment.
```

#### Configuration / first use

```bash
# Produce Zeek logs, then import and analyse them (command names vary by RITA version):
zeek -r capture.pcap
rita import ./ mydataset          # import the Zeek logs
rita show-beacons mydataset       # ranked beacon scores (1.0 = perfectly regular)
rita show-long-connections mydataset
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| Import fails / no DB | Match the datastore the installed version expects (e.g. MongoDB for older RITA); see its README. |
| No beacons found | You need **enough** connections over enough time; a short capture won't establish a cadence. |
| Command names differ | RITA's CLI changed across major versions; run `rita --help` for your build. |

---

## Part 3: Hands-on labs

You hunt the WS-ALICE **beacon**. `mk_beacon_pcap.py` writes a capture where the host calls the C2 `203.0.113.50:443` every ~60 s for 24 beacons, amid ordinary web traffic. **Suricata** runs for real — raising signature alerts and logging every flow; `eve_summary.py` reads its `eve.json`. Then `beacon_hunt.py` does RITA's core job — cadence analysis — on the capture. (Zeek and RITA couldn't be installed on this box; Part 2 has their steps, and `beacon_hunt.py` mirrors the `conn.log`-based analysis.)

Run on Ubuntu/SIFT. Reading a capture needs no root.

```bash
sudo apt update && sudo apt install -y suricata python3 git tcpdump
git -C ~/DFIR pull 2>/dev/null || git clone https://github.com/Mr-Phoenix07/DFIR.git ~/DFIR
mkdir -p ~/cases/LAB-029/{evidence,work,notes} && cd ~/cases/LAB-029
export TZ=UTC
python3 ~/DFIR/scripts/mk_beacon_pcap.py evidence/beacon.pcap
suricata -V 2>/dev/null
```

```
wrote evidence/beacon.pcap: 128 packets, 24 beacons + 8 noise connections
This is Suricata version 7.0.3 RELEASE
```

### Lab 1: Suricata — alert on the known, log everything (20 min)

Run Suricata over the capture with a rule for the known C2 IP, then read its `eve.json`:

```bash
suricata -r evidence/beacon.pcap -S ~/DFIR/scripts/day29.rules -l work --runmode single -k none > /dev/null 2>&1
python3 -I ~/DFIR/scripts/eve_summary.py work/eve.json
```

```
alerts: 24
  [24] WS-ALICE known C2 IP 203.0.113.50
flows logged: 32
flows by destination:
  203.0.113.50     24
  140.82.121.4     2
  142.250.72.14    2
  151.101.1.69     2
  93.184.216.34    2
```

Two things happened. The **signature** fired 24 times — once per call to the known-bad IP (that's the *known-threat* layer). And Suricata logged a **flow record for every connection**, alert or not — 32 flows, which grouped by destination already shout: **24** to `203.0.113.50`, two each to four ordinary sites. That log-everything habit (Zeek's whole purpose) is what lets the next step find a beacon the signatures didn't name.

### Lab 2: Beacon detection by cadence (20 min)

Volume alone isn't proof — a busy site gets many hits too. The beacon's signature is **regularity**. `beacon_hunt.py` groups connection starts by destination and measures the interval and its jitter:

```bash
python3 -I ~/DFIR/scripts/beacon_hunt.py evidence/beacon.pcap
```

```
destination              conns   mean_s  jitter_cv  verdict
203.0.113.50:443            24     60.0      0.041  BEACON
93.184.216.34:443            2    497.0      0.000  -
140.82.121.4:443             2    687.0      0.000  -
151.101.1.69:443             2    795.0      0.000  -
142.250.72.14:443            2    953.0      0.000  -
```

The C2 stands out and the busy-but-human destinations don't: **24 connections, a 60-second mean interval, and a coefficient of variation of 0.04** — a metronome. The ordinary sites have too few connections to score (and no rhythm). That low-jitter heartbeat is exactly what RITA ranks near 1.0 over Zeek's `conn.log`. Now you confirm the destination and check it isn't a legitimate 60-second poll — then it's C2.

---

## ✅ Knowledge check

1. Suricata, Zeek and RITA each represent a different NSM approach. Name the approach and the one thing each is best at.
2. Why do detection and hunting usually run on **logs/flows** rather than full PCAP, and what do you lose?
3. Define beaconing and name the single statistic that best separates a beacon from human browsing.
4. A destination got 500 connections today; another got 24. Which is more likely C2, and what do you measure to decide?
5. The C2 is HTTPS, so you can't read the payload. How do you still detect the beacon?
6. A real implant randomises its sleep by ±20%. Does that defeat cadence detection? Why or why not?
7. Your beacon detector flags an internal host hitting an update server every 3600 s. Beacon or not, and how do you resolve it?
8. Why keep Zeek logs for months but full PCAP for only days, and what does that trade-off cost you in an investigation?

<details>
<summary><b>Answers</b></summary>

1. **Suricata — signature IDS/IPS**, best at catching *known* threats (and blocking, inline). **Zeek — protocol logging**, best at producing the structured record (`conn.log`, `dns.log`, …) you hunt and query over. **RITA — behavioural analytics**, best at finding patterns across many connections (beaconing, long conns, rare FQDNs) that no single packet shows.
2. Logs/flows are **small and long-retained**, so you can query months of history and run analytics at scale; full PCAP is huge and kept only briefly. You lose the **payload** (and anything not captured in the log's fields) — you can see *that* a connection happened and its metadata, but not necessarily *what* was sent.
3. Beaconing = an implant **connecting to its C2 on a schedule**. The best single separator is the **coefficient of variation (stdev/mean) of the inter-arrival times** — low over many connections = regular = beacon; high or too-few = human.
4. The **24** is more likely C2 if its connections are **regular**; 500 bursty hits look like a human on a busy site. Decide by **cadence** (interval + jitter/CV), not volume — plus payload size consistency, destination rarity and duration.
5. Metadata: the **cadence** (interval/jitter), consistent **payload sizes**, the **TLS metadata** (SNI/JA3/JA4, certificate), and **destination reputation/age**. Encryption hides the content, not the rhythm.
6. **No, not by itself.** Detectors look at the **distribution** of intervals, not an exact period; ±20% jitter still leaves a tight, detectable cluster (a low-ish CV) distinct from human irregularity. Very large jitter plus low-and-slow timing is what degrades detection.
7. **Technically a beacon pattern, but likely benign** — a scheduled **update/telemetry poll**. Resolve by identifying the destination (vendor update server?), the process making the calls, and payload/volume; then **allow-list** the known-good regular traffic so it stops masking real C2.
8. Logs are **orders of magnitude smaller**, so months fit cheaply and enable **slow-pattern** detection (low-and-slow beacons, long-term trends); full PCAP is too big to keep long. The cost: once PCAP has rolled off, you **can't recover payloads/files** for an old event — you have the metadata but not the bytes, so you capture full PCAP at choke points and for active incidents.

</details>

---

## 📚 Further reading

- Zeek documentation (https://docs.zeek.org) — the log reference, `zeek-cut`, and writing detection scripts
- Suricata documentation (https://docs.suricata.io) — rules, `suricata-update`, EVE JSON, IDS vs IPS
- RITA / Active Countermeasures (https://github.com/activecm/rita) and the *Threat Hunting* material on beacon analysis
- Emerging Threats open rule set (https://rules.emergingthreats.net) and the Suricata rule-writing guide
- Applied NSM (Sanders & Smith); the SANS *Network Security Monitoring* material
- MITRE ATT&CK: **T1071** Application Layer Protocol, **T1573** Encrypted Channel, **T1008** Fallback Channels

---

## ⏭️ Tomorrow: Day 30

**Working with PCAP at scale.** Tools: **Arkime**, **Zui (Brimcap)**, **Malcolm**.
You've captured, dissected and monitored; tomorrow you index **large** PCAP — Arkime's searchable session database, Zui's Zeek+Suricata desktop workflow, and the Malcolm platform — so you can find the one flow in a terabyte.

---

<sub>Part of the <a href="../README.md">DFIR Daily</a> series · <a href="../CURRICULUM.md">Full 60-day curriculum</a> · For educational and authorised use only.</sub>
