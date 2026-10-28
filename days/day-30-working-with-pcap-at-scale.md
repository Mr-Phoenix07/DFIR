# Day 30: Working with PCAP at Scale

> **Phase 4: Network Forensics** · **Level:** 🔴 Advanced · **Time:** ~4 hours (reading + labs) · **Posted:** 2026-10-27
>
> **Tools today:** 🛠️ Arkime · 🛠️ Zui · 🛠️ Malcolm

---

## 🎯 Learning objectives

By the end of today you will be able to:

1. Explain why you **index and query** large captures instead of opening them in Wireshark, and what a **session record** is.
2. Describe the architecture of **Arkime**, **Zui** and **Malcolm**, and when each fits.
3. Reduce a capture to session records and **query at scale** — scale overview, top talkers, needle-in-haystack.
4. Find a beacon in tens of thousands of flows by **connection count and cadence**, not by volume.
5. Reason about storage, retention and pivoting — the practical limits of full-packet platforms.

---

## Part 1: The lesson

A day's traffic at a small office is already millions of packets; an enterprise is terabytes. You cannot open that in Wireshark, and `tcpdump | grep` won't scale. The tools today all solve the same problem the same way: **reduce packets to session records, index them, and query** — keeping the raw packets only as long as storage allows, retrievable by reference.

### 1.1 Session records and SPI

The unit of scale is the **session record** (Arkime calls its fields **SPI** — Session Profile Information): one row per connection with the 5-tuple, start/end times, byte and packet counts each way, the service/protocol, and extracted fields (HTTP host, TLS SNI, JA3, DNS names, file hashes). Thousands of packets collapse into one searchable row that **points back** to the packets on disk. Querying millions of rows is instant with an index; scanning the packets is not. This is exactly what Zeek's `conn.log` (Day 29) is — the platforms today just index it and bolt on a UI and packet retrieval.

### 1.2 Three platforms

- **Arkime** (formerly Moloch) — large-scale **full-packet capture + indexing**. Three parts: a **capture** process writing PCAP and SPI, **OpenSearch/Elasticsearch** storing the SPI, and a **viewer** web UI with a powerful session search (its own expression language) that can pull the raw packets for any session. Built for always-on perimeter capture at high rates.
- **Zui** (formerly Brim) — a **desktop app** for working a capture on your own machine. It runs **Zeek and Suricata** over a PCAP (via `brimcap`) and loads the results into a **Zed lake**, which you query with the **Zed language** (the `zq`/SuperDB engine). Great for an analyst with a PCAP and questions.
- **Malcolm** (CISA / INL) — a **turnkey Docker suite** that bundles Arkime, OpenSearch, Zeek, Suricata, dashboards (OpenSearch Dashboards), and file extraction/scanning. Stand up the whole NSM stack with `docker compose` rather than wiring it yourself.

They overlap: all turn PCAP into indexed, queryable records. Choose by setting — a sensor fleet (Arkime/Malcolm) vs an analyst's laptop (Zui).

### 1.3 The query mindset

At scale you don't read traffic — you **ask questions** and pivot:

- **Scale overview** — how many sessions, hosts, destinations, over what window.
- **Top talkers** — who moved the most bytes/sessions (finds noisy exfil, not quiet beacons).
- **Facets & filters** — by port/service, country, TLS SNI, HTTP host, JA3.
- **Behavioural** — many small connections to one destination (beacon), one very long connection, rare destinations.
- **Needle** — every session to an IOC (an IP, a domain, a JA3), then **retrieve the packets** for the few that matter.

The skill is expressing the question. Arkime has its expression syntax, Zui has Zed, Malcolm has OpenSearch/Dashboards — but the *questions* are the same, and they're the SQL-shaped queries in today's lab.

### 1.4 Storage, retention, pivoting

- **Storage.** Full PCAP is huge; SPI is ~1–2 orders of magnitude smaller. Shops keep **SPI/logs for months** and **full packets for days** (a rolling buffer), sized to a retention target.
- **Pivoting.** The point of indexing is to go from a lead (an IOC, a time window) to the exact sessions, then to the packets — in seconds. A record that can't pull its packets is just metadata.
- **Volume ≠ malice.** The loudest host is usually backups or a video call; the dangerous one is often **quiet and regular**. Rank by the right signal for the question.
- **Clock & dedup.** Across many sensors, normalise time (UTC) and deduplicate sessions seen at two taps, or counts mislead.

Today's labs can't stand up Arkime/OpenSearch, a Zed lake, or Malcolm's Docker stack on this box, so they use **SQLite** as the index-and-query engine over a large generated **session dataset** — the same records those platforms hold. The platforms are documented in Part 2.

---

## Part 2: Tools

All three are **platforms** (clusters, a desktop GUI, or a Docker suite), not single commands, and aren't stood up on this headless box — they're documented for a real deployment. The labs use **SQLite** over the session records they would index. `VER` is the version you fetch.

### 🛠️ Tool 1: Arkime

| | |
|---|---|
| **What** | Open-source, large-scale full-packet-capture and session-indexing system (formerly Moloch). |
| **Why** | Always-on capture at high rates with a searchable session database and one-click retrieval of the raw packets behind any session. |

#### Requirements

- Linux; **OpenSearch/Elasticsearch** (local or cluster); disk sized for your PCAP retention; the capture host needs the monitored interface.

#### Installation

```text
Install the Arkime package (version VER) from https://arkime.com/downloads for your distro, then run
its configure script and DB init (per the docs). Components: `arkime-capture`, the `viewer` (web UI),
and OpenSearch/Elasticsearch. Docs: https://arkime.com/settings
```

#### Configuration / first use

```text
1. Point capture at the interface (or import a PCAP):  arkime-capture -r capture.pcap
2. Browse the viewer (https://<host>:8005), log in, and search sessions with Arkime expressions, e.g.
     ip.dst == 203.0.113.50
     port.dst == 443 && bytes < 5000
     country.dst == RU
3. Open a session to see its SPI, then download the PCAP for just that session.
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| Viewer shows no sessions | OpenSearch not reachable / DB not initialised; check the capture process and the DB connection. |
| Disk fills | Full PCAP is large — set a retention/rollover policy and size storage to your window. |
| Import did nothing | Use `arkime-capture -r file.pcap` and confirm it indexed into the right DB prefix. |

### 🛠️ Tool 2: Zui (with Brimcap)

| | |
|---|---|
| **What** | A desktop app (formerly Brim) that turns a PCAP into Zeek + Suricata records in a **Zed lake**, queried with the **Zed** language. |
| **Why** | An analyst-friendly way to work a single capture: drop in a PCAP, get logs and alerts, pivot with queries, and open any flow's packets in Wireshark. |

#### Requirements

- Desktop OS (Windows/macOS/Linux) for the GUI. The `zq`/SuperDB CLI and `brimcap` can be used headless.

#### Installation

```text
Install Zui (version VER) from https://www.brimdata.io / https://github.com/brimdata/zui (desktop app).
Headless: the SuperDB CLI (zq) and brimcap from https://github.com/brimdata/super and
https://github.com/brimdata/brimcap turn a PCAP into queryable Zeek/Suricata logs.
```

#### Configuration / first use

```text
1. Open Zui and drag in capture.pcap — brimcap runs Zeek + Suricata and loads a Zed pool.
2. Query with Zed, e.g.:
     count() by id.resp_h | sort -r count          // top destinations
     event_type=="alert" | count() by alert.signature
     id.resp_h==203.0.113.50                         // the needle
3. Right-click a flow -> open its packets in Wireshark.
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| PCAP imports but no logs | brimcap couldn't run Zeek/Suricata; check the bundled tools/config. |
| Zed syntax errors | Zed is not SQL — see the language docs; pipe operators (`|`) chain operations. |
| Huge PCAP slow to load | Pre-filter with `tcpdump`/`editcap` to the window of interest before importing. |

### 🛠️ Tool 3: Malcolm

| | |
|---|---|
| **What** | A turnkey, Docker-based network traffic analysis suite (CISA / Idaho National Lab) bundling Arkime, OpenSearch, Zeek, Suricata and dashboards. |
| **Why** | Stand up a full NSM/forensics stack with `docker compose` instead of integrating the pieces yourself; strong on OT/ICS and file extraction. |

#### Requirements

- Docker + Docker Compose; substantial RAM/disk (it runs OpenSearch, Arkime, Zeek, Suricata, dashboards). Linux recommended.

#### Installation

```text
Clone Malcolm (version VER) from https://github.com/idaholab/Malcolm, run its install script, then
`docker compose up`. Follow the project README for sizing and configuration. Docs:
https://idaholab.github.io/Malcolm/
```

#### Configuration / first use

```text
1. Start the stack (docker compose up) and open the web UI.
2. Upload a PCAP (or feed a live interface); Zeek/Suricata/Arkime process it automatically.
3. Pivot in OpenSearch Dashboards and in the embedded Arkime viewer; extracted files are scanned.
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| Containers crash / OOM | OpenSearch needs plenty of RAM; raise limits and `vm.max_map_count` per the docs. |
| Nothing ingested | Check the upload/forwarder and that the Zeek/Suricata containers are healthy. |
| Overkill for one PCAP | For a single capture, use Zui; reserve Malcolm for a standing deployment. |

---

## Part 3: Hands-on labs

You can't run an OpenSearch cluster, a Zed lake or Malcolm's Docker stack here, so the labs use **SQLite** as the index-and-query engine over the **session records** those platforms hold. `mk_sessions.py` writes ~20,000 flows for an internal /24 over a day, with the WS-ALICE beacon hidden inside — your terabyte in miniature. The queries are the questions Arkime/Zui/Malcolm answer; only the engine differs.

Run on Ubuntu/SIFT. No root needed.

```bash
sudo apt update && sudo apt install -y sqlite3 python3 git
git -C ~/DFIR pull 2>/dev/null || git clone https://github.com/Mr-Phoenix07/DFIR.git ~/DFIR
mkdir -p ~/cases/LAB-030/{evidence,work,notes} && cd ~/cases/LAB-030
export TZ=UTC
python3 ~/DFIR/scripts/mk_sessions.py evidence/sessions.csv
rm -f work/net.db
sqlite3 work/net.db <<'EOF'
CREATE TABLE sessions(ts INTEGER,src_ip TEXT,src_port INTEGER,dst_ip TEXT,dst_port INTEGER,proto TEXT,service TEXT,duration REAL,src_bytes INTEGER,dst_bytes INTEGER,state TEXT);
.mode csv
.import --skip 1 evidence/sessions.csv sessions
CREATE INDEX idx_dst ON sessions(dst_ip,dst_port);
CREATE INDEX idx_flow ON sessions(src_ip,dst_ip,dst_port);
EOF
echo "indexed $(sqlite3 work/net.db 'SELECT count(*) FROM sessions;') sessions into work/net.db"
```

```
wrote evidence/sessions.csv: 20000 session records (200 of them a beacon)
indexed 20000 sessions into work/net.db
```

### Lab 1: Scale, and the top-talkers view (15 min)

First the questions a platform opens on — how big is this, and who's loudest:

```bash
echo '--- scale of the capture ---'
sqlite3 -header -column work/net.db "SELECT count(*) total, count(DISTINCT src_ip) internal_hosts, count(DISTINCT dst_ip) external_dsts FROM sessions;"
echo '--- top talkers by bytes (the view a big capture opens on) ---'
sqlite3 -header -column work/net.db "SELECT src_ip, count(*) flows, sum(src_bytes+dst_bytes) bytes FROM sessions GROUP BY src_ip ORDER BY bytes DESC, src_ip LIMIT 5;"
```

```
--- scale of the capture ---
total  internal_hosts  external_dsts
-----  --------------  -------------
20000  200             19801        
--- top talkers by bytes (the view a big capture opens on) ---
src_ip       flows  bytes  
-----------  -----  -------
10.20.30.28  182    8168422
10.20.30.55  179    8153865
10.20.30.54  183    7892855
10.20.30.41  175    7842411
10.20.30.45  175    7840355
```

Twenty thousand sessions, 200 internal hosts, nearly 20,000 external destinations — far past eyeballing. The **top talkers** are the heavy byte-movers (backups, downloads, video). Note what's **not** there: `10.20.30.40`, our beacon host, isn't in the top five — **volume doesn't find a beacon**. That's the trap of ranking by bytes.

### Lab 2: Find the needle by behaviour (15 min)

A beacon is many small connections to one destination. Group and count, instead of summing bytes:

```bash
echo '--- beacon candidates: many small connections to one destination ---'
sqlite3 -header -column work/net.db "SELECT src_ip, dst_ip, dst_port, count(*) conns, round(avg(src_bytes+dst_bytes)) avg_bytes FROM sessions GROUP BY src_ip, dst_ip, dst_port HAVING conns > 50 ORDER BY conns DESC, dst_ip LIMIT 5;"
```

```
--- beacon candidates: many small connections to one destination ---
src_ip       dst_ip        dst_port  conns  avg_bytes
-----------  ------------  --------  -----  ---------
10.20.30.40  203.0.113.50  443       200    1583.0   
```

One row stands out of 20,000: `10.20.30.40 → 203.0.113.50:443`, **200 connections**, averaging ~1.5 KB each — exactly the many-small-connections shape, and nothing legitimate matches it. The index made this instant; at Arkime/Malcolm scale it's the same query over OpenSearch.

### Lab 3: Confirm the cadence, then pull the sessions (15 min)

Count isn't proof — confirm the **rhythm**, then retrieve every session to the suspect (in Arkime you'd now click through to the packets):

```bash
echo '--- cadence of the suspect destination (gap histogram, seconds) ---'
sqlite3 -header -column work/net.db "WITH b AS (SELECT ts - LAG(ts) OVER (ORDER BY ts) gap FROM sessions WHERE dst_ip='203.0.113.50' AND dst_port=443) SELECT gap, count(*) n FROM b WHERE gap IS NOT NULL GROUP BY gap ORDER BY n DESC, gap LIMIT 5;"
echo '--- the needle: every session to the C2 ---'
sqlite3 -header -column work/net.db "SELECT count(*) conns, min(ts) first_seen, max(ts) last_seen, sum(src_bytes+dst_bytes) total_bytes FROM sessions WHERE dst_ip='203.0.113.50';"
```

```
--- cadence of the suspect destination (gap histogram, seconds) ---
gap  n  
---  ---
62   120
57   79 
--- the needle: every session to the C2 ---
conns  first_seen  last_seen   total_bytes
-----  ----------  ----------  -----------
200    1792003600  1792015543  316520     
```

The gaps cluster at ~60 seconds — a metronome, not human browsing — and the needle query returns all **200** sessions with the first/last times and total bytes for the report. From here a full-packet platform pivots straight to the raw packets of those 200 flows; the session index is what made finding them in 20,000 a single query.

---

## ✅ Knowledge check

1. Why index session records instead of searching the packets directly, and what does a session record keep that lets you still get the packets?
2. Arkime, Zui and Malcolm — match each to the setting it fits best.
3. You ranked hosts by bytes and the beacon host wasn't in the top 20. Why, and what should you rank by instead?
4. What is SPI in Arkime, and name three fields you'd filter on to chase a TLS-based C2?
5. A platform keeps SPI for 180 days but full PCAP for 5. You get an IOC for an event 3 weeks ago — what can and can't you recover?
6. Zui uses Zed, Arkime its own expression syntax, Malcolm OpenSearch queries. What stays the same across them?
7. Two sensors tap the same link and your "total sessions" doubled. What went wrong and how do you fix it?
8. For a single 2 GB PCAP from one host, which of today's tools is the pragmatic choice, and which is overkill?

<details>
<summary><b>Answers</b></summary>

1. Packets are too many to scan at scale; a **session record** (one row per connection: 5-tuple, times, byte/packet counts, service, extracted fields) is small and **indexable**, so queries over millions are instant. It keeps a **reference back to the packets** on disk, so you pivot from a matching record to its raw PCAP.
2. **Arkime** — always-on, high-rate perimeter/sensor **full-packet capture** with a cluster. **Zui** — an **analyst's desktop** working a single PCAP with Zeek/Suricata + Zed. **Malcolm** — a **turnkey Docker suite** to stand up the whole stack (good for OT/ICS and quick deployments).
3. Ranking by **bytes** finds noisy transfers; a beacon is **low-volume** (small, periodic). Rank by **connection count to a single destination** and **regularity (cadence/low jitter)**, plus consistent small payload sizes and rare destinations.
4. **SPI** = Session Profile Information: the indexed per-session fields. For TLS C2, filter on **destination IP/port**, **TLS SNI / server certificate**, and **JA3/JA4 fingerprint** (plus session count, bytes, and destination reputation/country).
5. You can recover the **metadata** (SPI/logs) for the event — who/when/how much, SNI/JA3, counts — but **not the packets/payloads**, because full PCAP from 3 weeks ago rolled off the 5-day buffer. Lesson: capture full PCAP longer at choke points, or for active incidents.
6. The **questions** — scale overview, top talkers, facet/filter by service/host/SNI/JA3, behavioural (beacon/long-conn/rare-dest), and needle-by-IOC then pivot to packets. Only the **query syntax** differs.
7. **Duplicate capture** — the same sessions seen at two taps were counted twice (no dedup / unclustered sensors). Fix by **deduplicating** sessions across sensors (and normalising time to UTC) so counts and bytes aren't inflated.
8. **Zui** is the pragmatic choice (drop in the PCAP, get Zeek/Suricata + queries on your laptop). **Malcolm/Arkime** (a cluster or full Docker suite) are **overkill** for one capture — they're for standing deployments.

</details>

---

## 📚 Further reading

- Arkime (https://arkime.com) — architecture, the viewer, and the session-search expression syntax
- Zui / Brimdata (https://www.brimdata.io, https://github.com/brimdata/zui) and the **Zed** language docs; `brimcap`
- Malcolm (https://github.com/idaholab/Malcolm, https://idaholab.github.io/Malcolm/) — deployment and sizing
- Arkime vs full-PCAP retention: the project's *FAQ* and scaling guides
- SANS *Network Forensics* and the Zeek/`conn.log` material from Day 29 (the records these platforms index)

---

## ⏭️ Tomorrow: Day 31

**Encrypted traffic: TLS, fingerprints (JA3/JA4) & decryption.** Tools: **mitmproxy**, **JA4+**, **PolarProxy**.
Most of what you indexed today is encrypted. Tomorrow: what TLS still reveals — SNI, certificates, and **JA3/JA4** client fingerprints — and when and how you can actually decrypt it.

---

<sub>Part of the <a href="../README.md">DFIR Daily</a> series · <a href="../CURRICULUM.md">Full 60-day curriculum</a> · For educational and authorised use only.</sub>
