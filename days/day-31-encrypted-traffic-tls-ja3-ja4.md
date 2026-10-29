# Day 31: Encrypted Traffic — TLS, Fingerprints (JA3/JA4) & Decryption

> **Phase 4: Network Forensics** · **Level:** 🔴 Advanced · **Time:** ~4 hours (reading + labs) · **Posted:** 2026-10-28
>
> **Tools today:** 🛠️ mitmproxy · 🛠️ JA4+ · 🛠️ PolarProxy

---

## 🎯 Learning objectives

By the end of today you will be able to:

1. Say what a TLS handshake still reveals **in the clear** — SNI, versions, cipher suites, ALPN, certificates — and what it hides.
2. Compute and use **JA3** and **JA4** client fingerprints, and explain why they survive changing IPs and domains.
3. Recognise how **ECH / encrypted SNI** and TLS 1.3 erode what you can see, and what fingerprints give you instead.
4. Decrypt TLS the two legitimate ways — a **MITM proxy** with a trusted CA (mitmproxy, PolarProxy) and **endpoint key logging** (`SSLKEYLOGFILE`) — and when each applies.
5. Treat a fingerprint as a **lead**, and handle decryption with the consent/authority it legally requires.

---

## Part 1: The lesson

Most of what you indexed in Days 28–30 is encrypted, and increasingly so. You will rarely read C2 payloads. But "encrypted" is not "invisible": the **handshake** that sets up TLS is in the clear, and it is remarkably characteristic of the client. Today is about reading that handshake, **fingerprinting** it, and — when you have the authority — **decrypting**.

### 1.1 What TLS reveals, and hides

A TLS session opens with a handshake. In the clear, before any encryption:

- The **ClientHello** advertises the **SNI** (the hostname the client wants — `cdn.ws-alice-c2.example`), the **TLS versions** it supports (via `supported_versions`), its ordered **cipher suites**, **extensions**, **ALPN** (`h2`, `http/1.1`), **supported groups** and **signature algorithms**.
- The **ServerHello** picks the version and cipher. In **TLS 1.2** the server **certificate** is sent in the clear (you see the subject, SAN, issuer, validity). In **TLS 1.3** the certificate is **encrypted**, so you lose that — but **SNI is still cleartext** (unless ECH, below).

Hidden: the application data (the HTTP request, the file, the credentials). So network forensics on TLS leans on **metadata and fingerprints**, not payload.

### 1.2 Fingerprinting the handshake: JA3 and JA4

The exact set and order of a client's cipher suites and extensions is a **signature of the software** (the TLS library, version, and options) — not of the destination. So two connections from the **same implant** to **different** C2 IPs/domains produce the **same** fingerprint. Two schemes:

- **JA3** (Salesforce, 2017): take five ClientHello fields — `SSLVersion,Ciphers,Extensions,EllipticCurves,PointFormats` — as decimal values joined with `-` and `,`, then **MD5** the string. Simple and widely supported, but brittle: it changes if the client shuffles ciphers, and MD5 is opaque.
- **JA4** (FoxIO, 2023): a human- and machine-readable **`a_b_c`** format — `a` = protocol+TLS-version+SNI-present+cipher-count+extension-count+ALPN; `b` = a truncated SHA-256 of the **sorted** cipher list; `c` = a truncated SHA-256 of the **sorted** extensions plus the signature algorithms. Sorting defeats the cipher-shuffling evasion that breaks JA3, and the readable `a` part lets you pivot on pieces (e.g. `ja4_ac`, dropping the variable `b`). JA4 is one of the **JA4+** suite (JA4S for servers, JA4H for HTTP, JA4X for certificates, JA4SSH, JA4T…).

Both are **durable IOCs**: you fingerprint the malicious TLS negotiation once and then find it again even as the C2's IPs and domains rotate. (They identify *software*, so benign apps share fingerprints too — a match is a lead, confirmed with context.)

### 1.3 What's eroding visibility

- **TLS 1.3** encrypts the certificate, removing a rich clear-text source; you still have SNI and the ClientHello fingerprint.
- **Encrypted Client Hello (ECH)** encrypts the SNI itself, so even the hostname goes dark; detection then leans harder on JA3/JA4, destination IP/ASN reputation, and JARM/JA4S (server fingerprints).
- **Domain fronting / CDNs** hide the true destination behind a shared front. Fingerprints and behaviour (Day 29) carry more weight as the clear-text shrinks.

### 1.4 Decrypting TLS — the two legitimate ways

You cannot "break" modern TLS; you decrypt it only with cooperation from one endpoint:

- **MITM proxy with a trusted CA.** A proxy (**mitmproxy**, **PolarProxy**) terminates the client's TLS, presents a certificate signed by a CA you installed as **trusted on the client**, and opens a new TLS session to the server — reading (and optionally writing decrypted PCAP) in between. Works only where you control the client's trust store (your own lab, a managed fleet, a sandbox). Install the CA, route traffic through the proxy.
- **Endpoint key logging.** If you control the client, set **`SSLKEYLOGFILE`**; the browser/app writes the per-session secrets, and Wireshark decrypts the capture with that key log — no MITM, no certificate warning. Ideal for malware sandboxes and your own hosts.

Both require **authority**: MITM-ing third-party TLS without consent is interception. Do it under policy/consent/warrant, and treat decrypted content as sensitive.

Today's labs **run for real** on a crafted TLS ClientHello: tshark reads its clear-text fields, and `ja_fingerprint.py` computes its JA3 and a spec-exact JA4. Decryption itself needs a live client and a trusted CA (or a key log), so mitmproxy/PolarProxy are documented, not run.

---

## Part 2: Tools

`ja_fingerprint.py` (the labs) computes JA3/JA4 for real. **mitmproxy**, **JA4+** tooling and **PolarProxy** need a live client, a CA, or platform integration, so they're documented. `VER` is the version you fetch.

### 🛠️ Tool 1: mitmproxy

| | |
|---|---|
| **What** | An interactive, scriptable HTTPS **man-in-the-middle proxy** (`mitmproxy` TUI, `mitmweb` UI, `mitmdump` CLI). |
| **Why** | Decrypt and inspect/modify TLS where you control the client trust store — lab analysis, malware sandboxes, API debugging — and script it in Python. |

#### Requirements

- Python 3; the client must **trust mitmproxy's CA** (installed from http://mitm.it while proxied). Traffic routed through it (explicit proxy or transparent mode).

#### Installation

```bash
pipx install mitmproxy            # or: pip install mitmproxy   (validated family: 10.x/11.x)
sudo apt install -y mitmproxy     # Debian/Ubuntu
brew install mitmproxy            # macOS
# Standalone binaries & docs: https://mitmproxy.org  ·  https://docs.mitmproxy.org
```

#### Configuration / first use

```bash
mitmproxy                                   # interactive TUI proxy on :8080
mitmdump -w flows.mitm                      # record flows to a file
mitmdump -r flows.mitm "~u /payload"        # replay/filter a saved flow file
# On the client: set the proxy to the mitm host:8080, browse to http://mitm.it, install the CA.
# Transparent mode (route via the host) + save decrypted traffic for analysis.
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| Certificate warnings / handshake fails | The client doesn't trust mitmproxy's CA — install it (http://mitm.it) in the client's trust store. |
| TLS 1.3 client refuses MITM | Some clients **pin** certificates or use mutual TLS; those can't be MITM'd — fall back to `SSLKEYLOGFILE`. |
| Nothing is intercepted | Traffic isn't routed through the proxy; set the client proxy or configure transparent mode. |

### 🛠️ Tool 2: JA4+ (fingerprints)

| | |
|---|---|
| **What** | FoxIO's suite of network fingerprints — JA4 (TLS client), JA4S (server), JA4H (HTTP), JA4X (x509), JA4T/JA4L/JA4SSH — in a readable `a_b_c` form. |
| **Why** | Durable IOCs that survive IP/domain rotation and resist the cipher-shuffling that breaks JA3; supported in Wireshark, Zeek, Suricata and Arkime. |

#### Requirements

- A capture or live traffic and a tool that computes the fingerprints: the FoxIO reference, a Wireshark build with JA4, or Zeek/Suricata. Note the **JA4+ licence** (the original JA4 is open; some of the suite is under FoxIO's licence) — check before commercial use.

#### Installation / use

```text
Reference implementations & spec: https://github.com/FoxIO-LLC/ja4  (Rust binary, Wireshark plugin,
Zeek/Suricata). Recent Wireshark exposes tls.handshake.ja4; Zeek/Suricata can log JA4 per connection.
Today's ja_fingerprint.py computes JA3 and JA4 (TLS client) from a ClientHello per the published spec.
```

```bash
# In the labs:
python3 ja_fingerprint.py capture.pcap     # -> SNI, version, JA3 (md5), JA4 (a_b_c)
# Pivot: hunt the JA4 across your Zeek/Suricata/Arkime data; drop the variable 'b' (ja4_ac) to
# track an actor who changes only cipher order.
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| JA3 differs for the "same" client | JA3 is order-sensitive and GREASE-sensitive; prefer JA4 (sorted) and ensure GREASE is ignored. |
| JA4 doesn't match another tool | Confirm both follow the current spec (version source `supported_versions`, SNI d/i, sorted b/c, sig-algs in order); check GREASE handling. |
| Only server traffic captured | Use JA4S (server hello) / JARM to fingerprint the server side. |

### 🛠️ Tool 3: PolarProxy

| | |
|---|---|
| **What** | Netresec's transparent **TLS-inspection proxy** that decrypts TLS and writes the **decrypted traffic to PCAP** (and can forward to Wireshark). |
| **Why** | Purpose-built for DFIR/malware labs: drop it inline, and get decrypted PCAP you analyse with your normal packet tools. |

#### Requirements

- Linux/Windows with the .NET runtime; the client must **trust PolarProxy's CA**; traffic routed through it. A sandbox/network you're authorised to intercept.

#### Installation / use

```text
Download PolarProxy (version VER) from https://www.netresec.com/?page=PolarProxy and run it; it
listens, decrypts, and writes decrypted PCAP. Install its generated CA on the client/sandbox. Follow
Netresec's docs for routing and the exact flags (don't assume options). Common pattern: decrypt a
sandbox VM's traffic to a .pcap you open in Wireshark.
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| Handshake failures | Client must trust PolarProxy's CA; pinned/mutual-TLS clients can't be intercepted. |
| No decrypted PCAP | Check routing (traffic must traverse the proxy) and the output path/flags per the docs. |
| Legal/consent concerns | Only intercept traffic you're authorised to; document consent/authority. |

---

## Part 3: Hands-on labs

You analyse the WS-ALICE host's TLS to its C2. `mk_tls_pcap.py` writes a capture with a real TLS 1.3 ClientHello (SNI `cdn.ws-alice-c2.example`). tshark reads its clear-text fields; `ja_fingerprint.py` computes the JA3 and JA4 client fingerprints (the JA4 matches FoxIO's published worked example exactly). Then a second capture to a different C2 shows the fingerprint is the same. Decryption needs a live client + trusted CA (Part 2), so it isn't run here.

Run on Ubuntu/SIFT. Reading a capture needs no root.

```bash
sudo apt update && sudo apt install -y tshark python3 git
git -C ~/DFIR pull 2>/dev/null || git clone https://github.com/Mr-Phoenix07/DFIR.git ~/DFIR
mkdir -p ~/cases/LAB-031/{evidence,work,notes} && cd ~/cases/LAB-031
export TZ=UTC
python3 ~/DFIR/scripts/mk_tls_pcap.py evidence/tls.pcap
tshark --version 2>/dev/null | head -n 1
```

```
wrote evidence/tls.pcap: 4 packets (TLS ClientHello, SNI cdn.ws-alice-c2.example)
TShark (Wireshark) 4.2.2 (Git v4.2.2 packaged as 4.2.2-1.1build3).
```

### Lab 1: Read the handshake without decrypting (10 min)

The ClientHello is in the clear — pull the fields that matter:

```bash
echo '--- what the TLS ClientHello reveals without any decryption ---'
tshark -r evidence/tls.pcap -Y 'tls.handshake.type==1' -T fields -e tls.handshake.extensions_server_name -e tls.handshake.extensions.supported_version -e tls.handshake.extensions_alpn_str 2>/dev/null
echo "cipher suites offered: $(tshark -r evidence/tls.pcap -Y 'tls.handshake.type==1' -T fields -e tls.handshake.ciphersuite 2>/dev/null | tr ',' '\n' | wc -l)"
```

```
--- what the TLS ClientHello reveals without any decryption ---
cdn.ws-alice-c2.example	0x0304	h2
cipher suites offered: 15
```

Without touching the encryption you already have the **destination name** (`cdn.ws-alice-c2.example`), the **version** (`0x0304` = TLS 1.3, from `supported_versions`), the **ALPN** (`h2`, HTTP/2), and that the client offered **15 cipher suites**. That's enough to recognise the service and to feed a fingerprint — even though every byte of the conversation that follows is encrypted.

### Lab 2: Fingerprint the client (JA3 and JA4) (20 min)

The cipher/extension profile identifies the *client software*. Compute both fingerprints:

```bash
python3 -I ~/DFIR/scripts/ja_fingerprint.py evidence/tls.pcap
```

```
SNI:      cdn.ws-alice-c2.example
version:  0x0304 (TLS 13)
ciphers:  15 offered
JA3:      c7240d90981bb4a546a859dd3bd5457c
JA4:      t13d1516h2_8daaf6152771_e5627efa2ab1
```

The **JA4** is `t13d1516h2_8daaf6152771_e5627efa2ab1` — `t` (TLS over TCP), `13` (TLS 1.3), `d` (has SNI), `15` ciphers, `16` extensions, `h2` (ALPN), then the sorted-cipher hash and the sorted-extension+sig-alg hash. (This is exactly FoxIO's published example, so you can check the implementation.) The **JA3** is the older MD5. Either is now an IOC you can hunt.

### Lab 3: Why fingerprints beat IPs and domains (15 min)

The attacker rotates C2 infrastructure constantly. Watch what the fingerprint does when the destination changes completely:

```bash
echo '--- a second capture: same client, different C2 name and IP ---'
python3 ~/DFIR/scripts/mk_tls_pcap.py evidence/tls2.pcap updates.cdn-fallback.example 198.51.100.77
echo 'capture 1:'; python3 -I ~/DFIR/scripts/ja_fingerprint.py evidence/tls.pcap | grep -E 'SNI|JA4'
echo 'capture 2:'; python3 -I ~/DFIR/scripts/ja_fingerprint.py evidence/tls2.pcap | grep -E 'SNI|JA4'
```

```
--- a second capture: same client, different C2 name and IP ---
wrote evidence/tls2.pcap: 4 packets (TLS ClientHello, SNI updates.cdn-fallback.example)
capture 1:
SNI:      cdn.ws-alice-c2.example
JA4:      t13d1516h2_8daaf6152771_e5627efa2ab1
capture 2:
SNI:      updates.cdn-fallback.example
JA4:      t13d1516h2_8daaf6152771_e5627efa2ab1
```

Two captures, two different C2 **names and IPs** — and the **same JA4**. That's the point: IPs and domains are cheap for an attacker to change, but the TLS client stack isn't. Fingerprint the malicious handshake once and you match it again across rotating infrastructure, where an IP or domain block-list would already be stale. (Benign software shares fingerprints too, so confirm with context before acting.)

---

## ✅ Knowledge check

1. List four things a TLS 1.3 handshake still exposes in the clear, and two it does not.
2. TLS 1.2 vs TLS 1.3: what clear-text source do you lose, and what do you keep?
3. In one sentence each, how are JA3 and JA4 computed, and why does JA4 resist an evasion that breaks JA3?
4. Two C2 connections go to different IPs and domains but share a JA4. What does that tell you, and what doesn't it?
5. What is ECH, and how does it change your approach to encrypted-traffic analysis?
6. You must read a malware sample's HTTPS C2 in a sandbox. Give two legitimate ways and the precondition each needs.
7. A JA4 matches a known-bad actor, but the host is a developer's laptop running a common tool. Beacon or false lead — how do you resolve it?
8. Why is MITM-decrypting arbitrary user TLS a legal/ethical problem, and what makes it acceptable?

<details>
<summary><b>Answers</b></summary>

1. Exposed: **SNI** (unless ECH), **TLS versions**, **cipher suites**, **extensions/ALPN/supported groups/signature algorithms**, destination **IP/port**, and in TLS 1.2 the **certificate**. Not exposed: the **application data** (HTTP request, files, credentials) and, in TLS 1.3, the **certificate** (encrypted).
2. You **lose the server certificate** in the clear (TLS 1.3 encrypts it); you **keep the SNI** (unless ECH) and the full **ClientHello fingerprint**.
3. **JA3** = MD5 of `SSLVersion,Ciphers,Extensions,EllipticCurves,PointFormats` (decimal, in order). **JA4** = a readable `a_b_c`: counts/version/SNI/ALPN, then SHA-256 of the **sorted** ciphers, then of the **sorted** extensions + sig-algs. JA4 **sorts** ciphers/extensions, so shuffling their order (which changes JA3) leaves JA4 unchanged.
4. Same JA4 ⇒ the **same client software/stack** is talking to both — strong evidence it's one implant across rotating infrastructure. It does **not** prove malice (benign tools share fingerprints) or that the two destinations are the same operator; confirm with context.
5. **Encrypted Client Hello** encrypts the SNI (and more of the ClientHello), so the **hostname goes dark**. You lean more on **JA3/JA4**, destination IP/ASN reputation, server fingerprints (JA4S/JARM) and behaviour (beaconing, Day 29).
6. **MITM proxy with a trusted CA** (mitmproxy/PolarProxy) — precondition: install the proxy's **CA as trusted** on the sandbox and route traffic through it. **`SSLKEYLOGFILE`** key logging — precondition: you **control the client** so it writes session keys, which Wireshark then uses. (Both fail against certificate-pinned clients → prefer the key log.)
7. Likely a **false lead** — JA4 identifies the **tool**, not intent; a common dev tool legitimately produces that fingerprint. Resolve by context: the **destination** (known-bad vs legit), the **cadence/volume** (Day 29), the **process** and user, and whether the rest of the behaviour is malicious — not the fingerprint alone.
8. It intercepts and reads **other people's private communications** — that's wiretapping/interception, which is unlawful without authority. It's acceptable only with proper **consent/policy/warrant** (your own hosts, a managed fleet that's been notified, a sandbox you own), and the decrypted data is handled as **sensitive**.

</details>

---

## 📚 Further reading

- FoxIO JA4+ spec and reference (https://github.com/FoxIO-LLC/ja4) — JA4/JA4S/JA4H/JA4X and the licence
- Salesforce JA3 (https://github.com/salesforce/ja3) and JARM (server fingerprinting)
- mitmproxy docs (https://docs.mitmproxy.org) — transparent mode, the CA, `mitmdump` scripting
- Netresec PolarProxy (https://www.netresec.com/?page=PolarProxy) — decrypting to PCAP
- Wireshark TLS wiki — `SSLKEYLOGFILE` decryption, and the TLS dissector fields
- RFCs 8446 (TLS 1.3) and the Encrypted Client Hello draft; the Fastly *State of TLS Fingerprinting* blog

---

## ⏭️ Tomorrow: Day 32

**Flow data & NetFlow/IPFIX analysis.** Tools: **nfdump**, **SiLK**, **softflowd**.
You've read packets, logs and TLS metadata; tomorrow we drop to the most compact network record of all — **flows** — generating NetFlow with softflowd and analysing it at scale with nfdump and SiLK.

---

<sub>Part of the <a href="../README.md">DFIR Daily</a> series · <a href="../CURRICULUM.md">Full 60-day curriculum</a> · For educational and authorised use only.</sub>
