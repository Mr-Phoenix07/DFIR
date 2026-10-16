# Day 19: Email Forensics: PST/OST, EML/MSG & Header Analysis

> **Phase 2: Windows Forensics** · **Level:** 🟡 Intermediate · **Time:** ~3.5 hours (reading + labs) · **Posted:** 2026-10-16
>
> **Tools today:** 🛠️ libpff (pffinfo, pffexport) · 🛠️ readpst (libpst) · 🛠️ eml_analyzer

---

## 🎯 Learning objectives

By the end of today you will be able to:

1. Say where email is stored (on the server, in Outlook's OST/PST files, as EML/MSG/mbox files) and which copy to collect for a question.
2. Identify a PST or OST from its header, export it with two independent tools, and explain why their counts or times can differ.
3. Read the **times** of a mail item correctly: sent, delivered, and created or modified **in this file**.
4. Take apart an **EML** (MIME parts, attachments, links, tracking images) and an Outlook **MSG** (a compound file of MAPI properties).
5. Read an email's **headers**: the Received chain bottom-up, the identity headers, and SPF, DKIM and DMARC verdicts, and say which parts you can trust.

---

## Part 1: The lesson

Email is still where most intrusions start (phishing) and where much of the evidence of what people agreed, sent or leaked ends up. It's also where investigators most often fool themselves: a display name, a `From:` line or a date is just text the sender typed. Today is about the containers mail lives in, getting it out of them without losing anything, and reading its headers.

### 1.1 Where mail lives

| Where | What you find | How to get it |
|---|---|---|
| **The server** (Exchange, Microsoft 365, Google Workspace, an IMAP host) | The authoritative mailbox, with server-side retention ("Recoverable Items", litigation hold) and logs (message trace, audit logs) | The mail administrator: eDiscovery / Content Search export (usually PST), message trace; provider legal process for personal accounts |
| **Outlook (classic) in cached mode: OST** | A local copy of the server mailbox: `%LOCALAPPDATA%\Microsoft\Outlook\<account>.ost` | Collect the file with Outlook closed (KAPE target `OutlookPSTOST`) |
| **PST** | Archives, exports, imported mail, POP3 accounts: `Documents\Outlook Files\*.pst` (Outlook 2010+); older: `%LOCALAPPDATA%\Microsoft\Outlook\` | Search the whole disk for `*.pst`: users keep them anywhere, including USB drives |
| **Opened attachments** | Outlook copies an attachment to a temporary folder when it's opened: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook\<random>\` | Collect the folder: files can stay there after the message is deleted |
| **EML / MSG files** | Single messages saved or dragged out of a mail client, or exported for a case | As files (hash them) |
| **Other clients** | Thunderbird: mbox files (one per folder, with a `.msf` index) under the profile's `Mail\` and `ImapMail\`; Apple Mail: `.emlx` files under `~/Library/Mail/` | The profile folders |
| **Webmail** (Outlook on the web, Gmail) | Nothing on disk except browser artifacts (Day 18) | From the server or provider |

**WS-ALICE:** Day 18 showed alice reading mail in **Outlook on the web** (`https://mail.corp.example/owa/`) in Edge, open all night. Webmail leaves no OST on the workstation, so her mailbox has to come from the Exchange server: ask the mail team for a hold and an export (PST) of `alice@corp.example`, plus a message trace for 2026-09-28 and 29, **before** retention policies delete anything.

The labs therefore use real, public mailbox files: a PST from the **Enron** corpus (released by the US regulator in 2003 and turned into PSTs by EDRM), an **outlook.com OST** made by the author of a PST parser for testing, a password-protected PST from a Java PST library's tests, and an Outlook **MSG** from an MSG reader's test set.

### 1.2 PST and OST files

PST (Personal Storage Table) and OST (Offline Storage Table) are the same format family, **PFF** (Personal Folder File), documented by Microsoft as **[MS-PST]**. Three layers: a **node database** of blocks and B-trees, **tables and property contexts** on top of it, and the **messaging** layer (folders, messages, recipients, attachments), where every item is a set of **MAPI properties**.

The header tells you what you have:

| Offset | Field | Values |
|---|---|---|
| 0 | magic | `!BDN` |
| 8 | client | `SM` = PST, `SO` = OST, `AB` = PAB (address book) |
| 10 | version | 14 or 15 = **ANSI** (Outlook 97–2002, 2 GB limit), 23 = **Unicode** (Outlook 2003+), 36 = **Unicode with 4 KB pages** (OST from Outlook 2013+, can be compressed) |
| 0x201 (Unicode) | encryption | 0 = none, 1 = "compressible" (a byte substitution), 2 = "high" (a cyclic cipher). Both are obfuscation, not protection: every tool reads them without a key |

Things that trip people up:

- **The PST password is not encryption.** It's a CRC-32 checksum of the password stored in the file; Outlook checks it, forensic tools ignore it (Lab 7).
- **An OST** is tied to the Outlook profile and the server mailbox: Outlook won't open it on another machine, but libpff and libpst read it. Since Outlook 2013 OSTs may be **compressed** (version 36).
- **Deleted items:** "Deleted Items" is just a folder. After it's emptied, the item lives on in the server's Recoverable Items (not in the OST/PST); inside the file, its blocks may survive until Outlook compacts it. `pffexport -m all` also exports **orphan and recovered** items from unallocated parts of the file.
- **Item types** are set by the message class: `IPM.Note` (email), `IPM.Schedule.Meeting.Request` (meeting request), `IPM.Appointment`, `IPM.Contact`, `IPM.DistList`, `IPM.Task`, `IPM.StickyNote`.

**Times.** An item has several, and only some describe the email:

| Property | Meaning |
|---|---|
| Client submit time (`PR_CLIENT_SUBMIT_TIME`) | When the sender's client sent it |
| Delivery time (`PR_MESSAGE_DELIVERY_TIME`) | When it was delivered to this mailbox |
| Creation time (`PR_CREATION_TIME`) | When the item was created **in this file or store**: a copy, an import or an export gets a new one |
| Modification time (`PR_LAST_MODIFICATION_TIME`) | When the item last changed **in this store** (read flag, category, move) |

In Lab 2 an Enron email sent in **2001** has a creation time in **2009**: the date EDRM built the PST, not anything Enron did. In the MSG of Lab 6 the email was sent in 2016 and saved as a file in 2018.

### 1.3 EML and MSG

**EML** is the Internet format itself (RFC 5322 + MIME): plain-text headers, a blank line, then the body. Multipart bodies hold the text and HTML versions and the attachments (usually base64), each part with its own `Content-Type` and `Content-Disposition` (`attachment` or `inline`). An **mbox** file is many EMLs one after another, each starting with a `From ` line.

**MSG** is Outlook's single-item file: a **Compound File** (OLE/CFB, like an old `.doc`) holding the item's MAPI properties as streams:

| Stream | Holds |
|---|---|
| `__substg1.0_0037001F` | Subject (property 0x0037, type 001F = Unicode string) |
| `__substg1.0_0C1A001F` / `0C1F001F` | Sender name / address |
| `__substg1.0_007D001F` | **Transport headers**: the original Internet headers of a received message (missing for drafts and most sent items) |
| `__substg1.0_1000001F`, `10130102` | Plain-text body, HTML body |
| `__properties_version1.0` | Fixed-size properties: times, flags, sizes |
| `__recip_version1.0_#00000000`... | One storage per recipient |
| `__attach_version1.0_#00000000`... | One per attachment (data in `__substg1.0_37010102`, name in `3707001F`) |

**Conversion changes things.** Exporting PST → EML or MSG rebuilds the message from MAPI properties: tools add headers of their own (readpst adds `X-libpst-forensic-sender` and `-bcc`), and some properties don't survive (Lab 6: readpst's MSG has no creation time). Keep the original container, hash it, and say which tool and version produced each export.

### 1.4 Reading headers

**Identity headers** are written by the sender and prove nothing on their own:

| Header | Set by | Notes |
|---|---|---|
| `From:` | the sender's client | Display name **and** address can be anything |
| `Reply-To:` | the sender's client | Where replies go; a mismatch with `From:` is common in bulk mail and in fraud |
| `Return-Path:` | the **receiving** server, from the SMTP envelope (`MAIL FROM`) | Where bounces go; the domain SPF checks |
| `Message-ID:` | the sender's client or first server | Unique; its domain often names the sending system |
| `Date:` | the sender's client | The sender's clock and time zone; compare with `Received:` times |

**`Received:` lines** are added by each server, newest **on top**, so read them **bottom-up**. Each says `from <who connected> by <this server>` and ends with that server's time. The line added by **your** boundary server (or your provider's) is the one to trust: it records the IP address that actually connected. Everything below it was written by servers you don't control and can be forged.

**Authentication** (recorded by the receiving server in `Authentication-Results:` at delivery):

| Check | What it verifies |
|---|---|
| **SPF** | The connecting IP is allowed to send for the envelope domain (`smtp.mailfrom`) |
| **DKIM** | A signature by domain `d=` over the body and listed headers is valid |
| **DMARC** | The `From:` domain **aligns** with the SPF domain or the DKIM domain (same registered domain), and SPF or DKIM passed; the domain owner's policy says what to do on failure |
| **compauth** | Microsoft's composite verdict (implicit authentication) |

A `Return-Path` that differs from `From:` is normal (bulk senders use bounce domains): Lab 5's genuine Microsoft email has a different bounce domain, a different `Reply-To` and a Message-ID from a marketing platform, and still passes DMARC through its DKIM signature. Judge by alignment and by the verdicts **your** server recorded. A DKIM check you run years later can fail (keys rotate, headers get rewritten), so treat it as supporting evidence.

**Provider headers** add more: Microsoft 365's `X-MS-Exchange-Organization-AuthAs` (`Anonymous` = came from the Internet, `Internal` = from inside the organisation), `X-MS-Exchange-Organization-SCL` (spam confidence), `X-Sender-IP`. A message with **no** `Received:` lines was created inside the mailbox system (a provider's welcome message, a draft, a sent item stored before transport).

**The HTML body** can carry **remote images**: an image URL unique to the recipient tells the sender when (and from which IP) the message was opened. **Links** usually go through click-tracking redirectors. Never open suspect mail in a normal client: parse it.

---

## Part 2: Tools

libpff and libpst are two independent implementations of the PST/OST format; using both is a cheap way to check one against the other. eml_analyzer takes apart single messages.

---

### 🛠️ Tool 1: libpff (pffinfo, pffexport)

| | |
|---|---|
| **What** | Joachim Metz's library for the PFF format (PST, OST, PAB), with `pffinfo` (file information) and `pffexport` (exports every item as a folder of text files: headers, body, recipients, attachments) |
| **Why in DFIR** | Exports **all** item types with their MAPI times and the original Internet headers, and can **recover orphan and deleted items** (`-m all`, `-m recovered`) |
| **Platforms** | Linux and macOS (build from source), Windows (Visual Studio solution in `msvscpp\`, or WSL); Python bindings `pypff` (PyPI package `libpff-python`) |
| **Licence** | LGPL-3.0-or-later; status "alpha" |
| **Home** | https://github.com/libyal/libpff |

#### Requirements

Linux (any distribution with the `pff-tools` package) or a C build environment. Ubuntu 24.04's package is version **20180714**; newer code is on GitHub and PyPI (`libpff-python` 20260926 at the time of writing).

#### Installation

```bash
# Ubuntu / Debian / SIFT (validated here: pffexport 20180714)
sudo apt install -y pff-tools
# Newer version from source (Linux/macOS): a release tarball from https://github.com/libyal/libpff/releases
tar xzf libpff-alpha-VER.tar.gz && cd libpff-VER && ./configure && make && sudo make install
# ...or from git: git clone https://github.com/libyal/libpff.git && cd libpff && ./synclibs.sh && ./autogen.sh, then ./configure && make
# Python bindings only
python3 -m pip install libpff-python
```

On Windows, use WSL (Ubuntu) with the apt package, or build `msvscpp\libpff.sln` with Visual Studio.

#### Configuration

| Option | Meaning |
|---|---|
| `pffinfo -a FILE` | Also show allocation information |
| `pffexport -t BASE` | Export to `BASE.export` (and `BASE.orphans`, `BASE.recovered`) |
| `-m items\|recovered\|all\|debug` | `items` (default): allocated items; `recovered`: orphan and recovered items; `all`: both; `debug`: also items outside the root folder |
| `-f text\|html\|rtf\|all` | Preferred body format (default text) |
| `-c CODEPAGE` | Code page of ANSI strings (default windows-1252) |
| `-d` | Dump all item values to `ItemValues.txt` |
| `-l LOGFILE`, `-q`, `-v` | Log exported items; quiet; verbose |

#### Verify the installation

```bash
pffexport -V | head -n 1        # pffexport 20180714
```

#### First use

```bash
pffinfo outlook.pst
pffexport -m all -l export.log -t case/outlook outlook.pst
```

Each message becomes a folder (`Message00001`) with `OutlookHeaders.txt` (MAPI times, subject, sender), `InternetHeaders.txt` (the original headers), `Recipients.txt`, `Message.txt`/`.html`/`.rtf` and `Attachments\`.

#### Troubleshooting

| Symptom | Fix |
|---|---|
| Errors or missing folders on a large or recent OST | The packaged 20180714 is old: try a newer libpff (GitHub or `libpff-python`) and cross-check with readpst |
| Garbled accented characters in an ANSI PST | Set the code page: `-c windows-1250` (etc.) |
| Nothing in `.recovered` | Normal if Outlook compacted the file; deleted mail may still be on the server |
| Export folder names collide with an earlier run | Use a new `-t` target per run |

---

### 🛠️ Tool 2: readpst (libpst)

| | |
|---|---|
| **What** | The libpst project's tools: `readpst` converts PST/OST to mbox, one EML per message, MH, KMail, MSG, vCard and iCalendar; `lspst` lists a file's folders and messages |
| **Why in DFIR** | Produces standard **EML/mbox** that any mail tool, e-discovery platform or script reads; `-D` includes deleted items; an independent check of libpff |
| **Platforms** | Linux (packaged); macOS and others from source; Windows through WSL |
| **Licence** | GPL-2.0 |
| **Home** | https://www.five-ten-sg.com/libpst/ · https://github.com/pst-format/libpst |

#### Requirements

Linux. Version 0.6.76 (2021) is the latest; OST 2013 support arrived in 0.6.71.

#### Installation

```bash
# Ubuntu / Debian / SIFT (validated here: 0.6.76)
sudo apt install -y pst-utils
# From a release tarball (any Unix): ./configure && make && sudo make install
```

On Windows, use WSL (Ubuntu) and the apt package.

#### Configuration

| Option | Meaning |
|---|---|
| `-o DIR` | Output folder (must exist) |
| `-e` | One `.eml` file per message (`-M`: the same, MH format without the extension; `-S`: "separate" format) |
| `-m` | Like `-e`, plus an Outlook `.msg` file per message |
| `-r` | Recursive: one mbox per folder, in a folder tree |
| `-D` | Include deleted items |
| `-8` | Bodies in UTF-8 where available |
| `-t eajc` | Item types to output: e-mail, attachments, journal, contacts |
| `-j N` | Parallel jobs. **Use `-j 0`** (no parallel jobs): see Troubleshooting |
| `-q`, `-d FILE`, `-L 1..3` | Quiet; debug log; debug level |
| `lspst -l FILE` | Also print date, CC and BCC for each message |

#### Verify the installation

```bash
readpst -V | head -n 1          # ReadPST / LibPST v0.6.76
```

#### First use

```bash
mkdir -p case/eml && readpst -j 0 -D -e -8 -o case/eml outlook.pst
lspst -l outlook.pst > case/listing.txt
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| **Different numbers of files on repeated runs** | readpst 0.6.76's default parallel mode is not reliable: on the same Enron PST it wrote 69, 70 or 71 EMLs on four runs (and numbered them differently). With **`-j 0`** it wrote all 71, identically, every time. Always use `-j 0` and compare the count with `lspst` |
| "Cannot change to output dir" | Create the `-o` folder first |
| "N items skipped" | Items it didn't convert (other item types or ones it can't read): compare with `lspst` and pffexport before you conclude a folder is complete |
| Headers like `X-libpst-forensic-sender` | Added by readpst, not part of the original message |

---

### 🛠️ Tool 3: eml_analyzer (emlAnalyzer)

| | |
|---|---|
| **What** | Florian Wahl's command-line analyzer for `.eml` files: headers, MIME structure, attachments (list and extract), URLs, and **reloaded content** (remote images, i.e. tracking pixels), with optional JSON output |
| **Why in DFIR** | Takes apart a suspect message without opening it in a mail client; JSON output for scripting. (Not to be confused with **ninoseki's EML Analyzer**, a web application with IOC extraction and VirusTotal/urlscan lookups, shipped as a Docker image on GHCR) |
| **Platforms** | Python 3 on Windows, Linux and macOS |
| **Licence** | MIT |
| **Home** | https://github.com/wahlflo/eml_analyzer |

#### Requirements

Python 3 with `pip`. It reads EML; convert MSG or PST items to EML first (readpst `-e`).

#### Installation

```bash
# Linux / macOS (validated here: 3.0.1), in a virtual environment
python3 -m venv ~/tools/mail-venv
~/tools/mail-venv/bin/pip install eml-analyzer==3.0.1
```

```powershell
# Windows
py -m pip install eml-analyzer
emlAnalyzer --help
```

#### Configuration

| Option | Meaning |
|---|---|
| `-i FILE` | The EML file (standard input if omitted) |
| `--header` | All headers |
| `-s`, `--structure` | The MIME tree |
| `-a`, `--attachments` | List attachments |
| `-ea N`, `--extract N` / `--extract-all` | Extract one or all attachments; `-o PATH` sets where |
| `-u`, `--url` | Links and URLs in the text and HTML parts |
| `-x`, `--tracking` | Content loaded from external resources (remote images) |
| `--text`, `--html` | Print the bodies |
| `--format json` | Structured output (with `--extract-all`, attachments included as base64) |

#### Verify the installation

```bash
~/tools/mail-venv/bin/pip show eml-analyzer | grep ^Version        # Version: 3.0.1
```

#### First use

```bash
emlAnalyzer -i suspect.eml -s -a -u -x
emlAnalyzer -i suspect.eml --extract-all -o case/attachments
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| `BrokenPipeError` when piping to `head` | It stops when the pipe closes; use `grep` or redirect to a file instead |
| The order of URLs changes between runs | It doesn't sort them: pipe through `sort` (Lab 5) |
| An MSG file isn't parsed | Convert it to EML first, or read it with `msg_props.py` / an MSG library |
| Attachment names with odd characters | Extract with `-o` to a folder you control; never open them on the analysis host |

---

## Part 3: Hands-on labs

Real, public data, pinned to fixed commits: the **Enron PST** and an **outlook.com OST** from the test set of the `pst-extractor` project, a **password-protected PST** from `java-libpst`'s tests, and an **Outlook MSG** from `MSGReader`'s test set. Two helper scripts from this repo: `mail_hops.py` (headers) and `msg_props.py` (MSG files).

Run on Ubuntu 24.04 or SIFT.

```bash
sudo apt update && sudo apt install -y git curl pff-tools pst-utils python3-venv file
git -C ~/DFIR pull 2>/dev/null || git clone https://github.com/Mr-Phoenix07/DFIR.git ~/DFIR
mkdir -p ~/cases/LAB-019/{samples,work,notes} ~/tools && cd ~/cases/LAB-019
export TZ=UTC
```

Install eml_analyzer (and olefile, for `msg_props.py`) in a virtual environment and check the versions:

```bash
[ -d ~/tools/mail-venv ] || python3 -m venv ~/tools/mail-venv
~/tools/mail-venv/bin/pip install -q eml-analyzer==3.0.1 olefile==0.47 2> /dev/null
emlanalyzer() { ~/tools/mail-venv/bin/emlAnalyzer "$@"; }
pffexport -V | head -n 1
readpst -V | head -n 1
echo "eml-analyzer $(~/tools/mail-venv/bin/pip show eml-analyzer | sed -n 's/^Version: //p')"
```

```
pffexport 20180714
ReadPST / LibPST v0.6.76
eml-analyzer 3.0.1
```

### Lab 1: Identify the containers (15 min)

```bash
PE=https://raw.githubusercontent.com/epfromer/pst-extractor/7d08ef9bc7112c23275fa948306c76bba6e24fba/src/__tests__/testdata
JLP=https://raw.githubusercontent.com/rjohnsondev/java-libpst/f158a64acf2a0e46ac3bd699bc7a5a8da6c40d26/src/test/resources
MR=https://raw.githubusercontent.com/Sicos1977/MSGReader/b9b04a7aef354c12872b48c29da87ba247f6b46b/MsgReaderTests/SampleFiles
curl -sSfL -o samples/enron.pst $PE/enron.pst
curl -sSfL -o samples/outlookcom.ost "$PE/pstextractortest%40outlook.com.ost"
curl -sSfL -o samples/passworded.pst $JLP/passworded.pst
curl -sSfL -o samples/EmailWithAttachments.msg $MR/EmailWithAttachments.msg
(cd samples && sha256sum * | cut -c1-16,65- | tee ../notes/samples.sha256)
for f in samples/*.pst samples/*.ost; do
  python3 - "$f" <<'EOF'
import struct, sys
h = open(sys.argv[1], "rb").read(1024)
magic, _, client, ver = struct.unpack_from("<4sI2sH", h, 0)
kind = {14: "ANSI", 15: "ANSI", 23: "Unicode", 36: "Unicode, 4 KB pages"}.get(ver, "?")
print(f"{sys.argv[1]:<26} {magic.decode()}  {client.decode()}  version {ver} ({kind})  crypt byte {h[0x201]}")
EOF
done
for f in samples/enron.pst samples/outlookcom.ost samples/passworded.pst; do
  echo "$f: $(pffinfo $f | grep -E 'content type|File type|Encryption|Password' | cut -d: -f2 | xargs | tr '\n' ' ')"
done
```

```
59d2f6bd9287b77b  EmailWithAttachments.msg
6152489de3472be6  enron.pst
daacd8d441428634  outlookcom.ost
e1085e210bc823fc  passworded.pst
samples/enron.pst          !BDN  SM  version 23 (Unicode)  crypt byte 1
samples/passworded.pst     !BDN  SM  version 23 (Unicode)  crypt byte 1
samples/outlookcom.ost     !BDN  SO  version 36 (Unicode, 4 KB pages)  crypt byte 0
samples/enron.pst: Personal Storage Tables (PST) 64-bit compressible N/A 
samples/outlookcom.ost: Offline Storage Tables (OST) 64-bit with 4k page none N/A 
samples/passworded.pst: Personal Storage Tables (PST) 64-bit compressible 0xe61eb50f 
```

- The two PSTs are **Unicode** (version 23) and "compressible" (crypt byte 1), the OST is version **36**: an Outlook 2013+ OST with 4 KB pages. `pffinfo` agrees on each.
- `passworded.pst` has a **password checksum**; Lab 7 shows how little it protects.

### Lab 2: pffexport and the item times (25 min)

```bash
pffexport -q -m all -t work/enron samples/enron.pst > /dev/null
ls work
find work/enron.export -type d -name 'Message?????' | sed 's#/Message[0-9]*$##; s#.*/##' | sort | uniq -c
M="work/enron.export/Top of Personal Folders/lokay-m/MLOKAY (Non-Privileged)/Sent Items/Message00001"
ls "$M"
grep -E 'time:|Subject:|Sender name:' "$M/OutlookHeaders.txt"
grep -E '^(Message-ID|filename|folder):' "$M/InternetHeaders.txt"
```

```
enron.export
      1 MLOKAY (Non-Privileged)
     47 Personal
      2 Sent Items
      7 Systems
     14 TW-Commercial Group
ConversationIndex.txt
InternetHeaders.txt
Message.txt
OutlookHeaders.txt
Recipients.txt
Client submit time:			Oct 30, 2001 03:52:40.000000000 UTC
Delivery time:				Oct 30, 2001 03:52:40.000000000 UTC
Creation time:				May 11, 2009 19:17:18.545000000 UTC
Modification time:			May 11, 2009 19:17:18.545000000 UTC
Subject:				Cirque du Soleil - Dralion
Sender name:				Lokay
Message-ID: <CTBITLRPOWHBS4AJABL1YK4IP2J3324IA@zlsvr22>
filename: LDONOHO (Non-Privileged).pst
folder: \LDONOHO (Non-Privileged)\Inbox
```

- 71 messages in five folders. Each message is a folder of text files.
- **Sent 2001-10-30 03:52:40 UTC, created 2009-05-11.** The creation and modification times are when EDRM wrote this item into this PST. On a suspect's own mailbox, the same pattern (old sent date, recent creation time) is what an imported, copied or **planted** item looks like: compare with the delivery time and the server's message trace.
- `InternetHeaders.txt` has headers EDRM added (`filename:`, `folder:`), naming the PST and folder the item came from. Headers can be added by whoever handled the data.

### Lab 3: readpst and lspst: a second opinion (20 min)

```bash
lspst samples/enron.pst | head -n 5
lspst samples/enron.pst | cut -f1 | sort | uniq -c
mkdir -p work/readpst && readpst -q -j 0 -D -e -8 -o work/readpst samples/enron.pst
find work/readpst -name '*.eml' | wc -l
head -n 12 "work/readpst/Personal folders/lokay-m/MLOKAY (Non-Privileged)/Sent Items/1.eml"
```

```
Folder "lokay-m"
Folder "MLOKAY (Non-Privileged)"
Folder "TW-Commercial Group"
Email	From: Lee  Dennis	Subject: New OBA's
Email	From: Reames Julie	Subject: I/B Link Capacity for November and December 2001
     71 Email
      1 Folder "MLOKAY (Non-Privileged)"
      1 Folder "Personal"
      1 Folder "Sent Items"
      1 Folder "Systems"
      1 Folder "TW-Commercial Group"
      1 Folder "lokay-m"
71
date: Mon, 29 Oct 2001 19:52:40 -0800 (PST) Mon, 29 Oct 2001 19:52:40 -0800  (PST)
Message-ID: <CTBITLRPOWHBS4AJABL1YK4IP2J3324IA@zlsvr22>
from: Lokay
to: Harris, Steven </O=ENRON/OU=NA/CN=RECIPIENTS/CN=Sharris1>, Watson, Kimberly
cc: Lokay, Michelle </O=ENRON/OU=NA/CN=RECIPIENTS/CN=Mlokay>
subject: Cirque du Soleil - Dralion
filename: LDONOHO (Non-Privileged).pst
folder: \LDONOHO (Non-Privileged)\Inbox
Status: RO
X-libpst-forensic-sender: Lokay
X-libpst-forensic-bcc: 
MIME-Version: 1.0
```

`lspst`, readpst and pffexport all count **71** messages. readpst rebuilt each message as an EML from the stored headers and added two `X-libpst-forensic-*` headers of its own. (Without `-j 0`, this same command wrote 69 to 71 files on different runs: see readpst's Troubleshooting.)

### Lab 4: An outlook.com OST (20 min)

```bash
mkdir -p work/ost-eml && readpst -j 0 -e -8 -o work/ost-eml samples/outlookcom.ost | grep -E '"(Inbox|Sent Items|Calendar)"'
find work/ost-eml -name '*.eml' | sed 's#/[0-9]*\.eml$##' | sort | uniq -c
pffexport -q -t work/ost samples/outlookcom.ost > /dev/null
find work/ost.export -type d -regex '.*/[A-Za-z]+[0-9][0-9][0-9][0-9][0-9]' | grep -E '/(Inbox|Sent Items)/' | sed -E 's#.*/(Inbox|Sent Items)/([A-Za-z]+)[0-9]+$#\1 \2#' | sort | uniq -c
```

```
Processing Folder "Inbox"
	"Inbox" - 10 items done, 13 items skipped.
Processing Folder "Sent Items"
	"Sent Items" - 2 items done, 0 items skipped.
Processing Folder "Calendar"
	"Calendar" - 11 items done, 6 items skipped.
     10 work/ost-eml/outlookcom.ost/Inbox
      2 work/ost-eml/outlookcom.ost/Sent Items
      1 work/ost-eml/outlookcom.ost/Sync Issues
      3 Inbox Meeting
      7 Inbox Message
      2 Sent Items Meeting
```

Both tools read the compressed 2013-format OST. They agree on the Inbox (10 items: 7 messages and 3 meeting requests in pffexport's names) but readpst also reports **13 skipped** Inbox items, and filed one item under "Sync Issues". Before you tell anyone "the Inbox held 10 items", find out what the 13 are (pffexport `-m all`, `pffinfo -a`, or a third tool).

### Lab 5: Headers, tracking and links (30 min)

```bash
I="work/ost-eml/outlookcom.ost/Inbox"
python3 ~/DFIR/scripts/mail_hops.py "$I/1.eml" "$I/2.eml"
emlanalyzer -i "$I/1.eml" -x | grep -c ' - http'
emlanalyzer -i "$I/1.eml" -x | grep -o 'https\?://[^ ]*open\.aspx' | sort -u
emlanalyzer -i "$I/1.eml" -u | grep -o 'https\?://[^/]*' | sort | uniq -c
```

```
== work/ost-eml/outlookcom.ost/Inbox/1.eml
Subject:     Get started with OneDrive
From:        "Microsoft OneDrive" <email@mail.onedrive.com>
Reply-To:    "No Reply OneDrive" <reply-fec910747466017b-25_HTML-1813406656-7231722
Return-Path: bounce-25_HTML-1813406656-441256-7231722-1211813@bounce.microsoftemail
Message-ID:  <f97f5b93-8409-4218-b364-88f6cbf06c71@atl1s07mta2707.xt.local>
Date:        Thu, 12 Aug 2021 14:18:00 -0600  =  2021-08-12 20:18:00 UTC
Received:    5 hop(s), oldest first
  1  2021-08-12 20:18:00        from -
                                by   mta39.email2.microsoft.com
  2  2021-08-12 20:18:00   +0s  from mta39.email2.microsoft.com [136.147.186.39]
                                by   DM6NAM11FT016.mail.protection.outlook.com
  3  2021-08-12 20:18:01   +1s  from DM6NAM11FT016.eop-nam11.prod.protection. [2603:10b6:5:3b3:cafe::95]
                                by   DS7PR03CA0258.outlook.office365.com
  4  2021-08-12 20:18:01   +0s  from DS7PR03CA0258.namprd03.prod.outlook.com [2603:10b6:5:3b3::23]
                                by   SJ0PR03MB6598.namprd03.prod.outlook.com
  5  2021-08-12 20:18:02   +1s  from SJ0PR03MB6598.namprd03.prod.outlook.com [2603:10b6:a03:38a::21]
                                by   BN7PR03MB3762.namprd03.prod.outlook.com
Auth:        spf=pass dkim=pass dmarc=pass (DMARC checked the From domain mail.onedrive.com)
  SPF domain  bounce.microsoftemails.com   aligned with mail.onedrive.com: no
  DKIM domain mail.onedrive.com            aligned with mail.onedrive.com: yes

== work/ost-eml/outlookcom.ost/Inbox/2.eml
Subject:     Welcome to your new Outlook.com account
From:        "Outlook Team" <no-reply@microsoft.com>
Reply-To:    -
Return-Path: -
Message-ID:  <BN7PR03MB376291475B4F801F0BCB56A6CDF99@BN7PR03MB3762.namprd03.prod.ou
Date:        Thu, 12 Aug 2021 20:16:07 +0000  =  2021-08-12 20:16:07 UTC
Received:    none (created inside the mailbox system)

15
https://click.mail.onedrive.com/open.aspx
      1 http://www.w3.org
     15 https://click.mail.onedrive.com
     16 https://i.s-microsoft.com
      1 https://view.mail.onedrive.com
```

Read message 1 the way you'd read a suspect one:

- **Identity:** `From:` is `mail.onedrive.com`, `Reply-To:` is another address, `Return-Path:` is a bounce address at `bounce.microsoftemails.com`, and the Message-ID ends in `xt.local`, an internal host name of the bulk-mail platform that sent it (not a public domain). Four different "senders", all normal for marketing mail.
- **Route (bottom-up):** hop 1 is the bulk-mail server stamping it, hop 2 is the connection into Microsoft's protection servers from **136.147.186.39**: the IP address the receiving side actually saw, and the one SPF checked. Hops 3–5 are inside Microsoft 365 (IPv6), two seconds in total. The `Date:` header (14:18:00 −06:00 = 20:18:00 UTC) matches.
- **Authentication:** SPF passed for the bounce domain, which does **not** align with the From domain; DKIM passed for `mail.onedrive.com`, which **does**; so DMARC passed. This is why "Return-Path ≠ From" alone proves nothing.
- **Message 2** has no `Received:` lines: Outlook.com created it inside the mailbox.
- **Tracking:** 15 remote images, one of them `click.mail.onedrive.com/open.aspx`: an **open-tracking** URL. Loading the images tells the sender the message was opened, when, and from which IP. The links all go through `click.mail.onedrive.com` (click tracking).

### Lab 6: Attachments and an Outlook MSG (20 min)

```bash
emlanalyzer -i "$I/7.eml" -s -a
emlanalyzer -i "$I/7.eml" --extract-all -o work/attachments > /dev/null
for f in work/attachments/*; do echo "$(sha256sum < "$f" | cut -c1-16)  $(file -b "$f" | cut -d, -f1)  ${f##*/}"; done
```

```
 =================
 ||  Structure  ||
 =================
|- multipart/mixed                       
|  |- text/html                          
|  |- text/plain                           [text.txt]
|  |- image/jpeg                           [primoz-roglic-of-slovenia-and-team-jumbo-visma-red-leader-news-photo-1628610563.jpg]
|  |- application/pdf                      [Clinometer Usage.pdf]

 ===================
 ||  Attachments  ||
 ===================
[1] text.txt                                                                                   text/plain             attachment
[2] primoz-roglic-of-slovenia-and-team-jumbo-visma-red-leader-news-photo-1628610563.jpg        image/jpeg             attachment
[3] Clinometer Usage.pdf                                                                       application/pdf        attachment

36a917a48e7b93f5  PDF document  Clinometer Usage.pdf
755560d196b67580  JPEG image data  primoz-roglic-of-slovenia-and-team-jumbo-visma-red-leader-news-photo-1628610563.jpg
479b060322517dbb  ASCII text  text.txt
```

Extract, hash and identify attachments by their content (`file`, Day 8), never by their names. Then the MSG files:

```bash
cp samples/EmailWithAttachments.msg work/ && file -b work/EmailWithAttachments.msg
~/tools/mail-venv/bin/python -I ~/DFIR/scripts/msg_props.py work/EmailWithAttachments.msg
mkdir -p work/readpst-msg && readpst -q -j 0 -m -o work/readpst-msg samples/enron.pst
~/tools/mail-venv/bin/python -I ~/DFIR/scripts/msg_props.py "work/readpst-msg/Personal folders/lokay-m/MLOKAY (Non-Privileged)/Sent Items/1.msg"
```

```
CDFV2 Microsoft Outlook Message
== work/EmailWithAttachments.msg: 63 streams, 3 recipient(s), 2 attachment(s)
  Subject                This is the subject
  Sender name            Kees
  Sender address         peterpan@neverland.com
  Display To             crocodile@neverland.com
  Display Cc             tinkerbel@neverland.com
  Body (plain text)      Hello Neverland text
  Client submit time     2016-12-03 18:08:54 UTC
  Creation time          2018-01-26 17:37:40 UTC
  Last modification time 2018-01-26 17:37:40 UTC
  attachment 00000000    39150 bytes  image/jpeg               peterpan.jpg
  attachment 00000001    49353 bytes  image/jpeg               tinkerbell.jpg
== work/readpst-msg/Personal folders/lokay-m/MLOKAY (Non-Privileged)/Sent Items/1.msg: 38 streams, 3 recipient(s), 0 attachment(s)
  Subject                Cirque du Soleil - Dralion
  Sender name            Lokay
  Sender address         Lokay
  Sent-repr. address     Lokay
  Display To             harris; Steven; watson; kimberly
  Display Cc             lokay; Michelle
  Internet Message-ID    <CTBITLRPOWHBS4AJABL1YK4IP2J3324IA@zlsvr22>
  Transport headers      date: Mon, 29 Oct 2001 19:52:40 -0800 (PST) Mon, 29 Oct 2001 19:52:40   (+7 more lines)
  Body (plain text)      Mark your calendars!  The Transwestern Commercial group is confirmed f  (+12 more lines)
  Client submit time     2001-10-30 03:52:40 UTC
```

- The real Outlook MSG: sent **2016-12-03**, created **2018-01-26**, when it was saved as a file. Two attachments with their MIME types and sizes, read from the compound file without Outlook.
- The MSG that readpst made from the Enron PST has the **transport headers** and the Internet Message-ID, but **no creation or modification time**: the conversion dropped them. Know what your export format keeps.

### Lab 7: The PST "password" (10 min)

```bash
pffinfo samples/passworded.pst | grep -E 'Password'
pffexport -q -t work/passworded samples/passworded.pst > /dev/null
find "work/passworded.export/Top of Personal Folders/Contacts" -mindepth 1 -maxdepth 1 | sed 's#.*/##' | sort
grep -E '^(Display name|Given name|Surname|Creation time)' "work/passworded.export/Top of Personal Folders/Contacts/Contact00002/Contact.txt" 2> /dev/null | head -n 6
```

```
	Password checksum:	0xe61eb50f
Contact00002
DistributionList00001
Creation time:				May 25, 2014 13:58:28.377000000 UTC
Display name:				contact name 1
Given name:				contact
Surname:				1
```

pffexport exported the contents of the password-protected PST without being given any password. The PST password is a checksum Outlook checks; it doesn't encrypt anything. (Outlook's separate S/MIME and Microsoft Purview message encryption do protect message bodies: those need the keys.)

---

## ✅ Knowledge check

1. A user read all their mail in Outlook on the web. What will you find on their workstation, and where do you get the mailbox?
2. How do you tell a PST from an OST, and an ANSI PST from a Unicode one, from the first bytes of the file?
3. A message in a suspect's PST was sent in 2019 but has a creation time of last week. Give two explanations and how you'd tell them apart.
4. Why should you run readpst with `-j 0`, and what check catches the problem anyway?
5. A message has five `Received:` lines. Which one do you trust most, and why?
6. SPF passed, DKIM passed, DMARC failed. How is that possible?
7. What does a remote image in an HTML email tell the sender, and what does that mean for how you analyse suspect mail?
8. Where in an MSG file are the original Internet headers, and why might they be missing?

<details>
<summary><b>Answers</b></summary>

1. No OST or PST: only browser artifacts (history, cache, cookies: Day 18). Get the mailbox from the server: a hold, then an eDiscovery/Content Search export (PST) by the mail administrator, plus a message trace and audit logs.
2. Both start with `!BDN`; bytes 8–9 are `SM` for a PST and `SO` for an OST. The version at offset 10 is 14 or 15 for ANSI, 23 for Unicode, 36 for an OST with 4 KB pages (Outlook 2013+).
3. The item was **copied, imported or moved into this file** recently (an archive, an export, a restore), or it was **created or edited** recently (a planted or altered message: MAPI tools can create items with any "sent" date). Compare with the delivery time, the server's message trace and the server copy, the headers (do the `Received:` times match the sent date?), and other copies held by the recipients.
4. Its default parallel mode can drop or renumber messages (69–71 of 71 in our tests). Compare the number of exported messages with `lspst` and with a second tool (pffexport).
5. Read bottom-up; trust the line added by **your own** (or your provider's) receiving server, recording the IP that connected to it. Lines below it were written by systems you don't control.
6. DMARC also needs **alignment**: SPF passed for a different envelope domain and DKIM was signed by a different domain than the `From:` domain, so neither aligned. That's typical of spoofing the `From:` domain while sending from your own infrastructure.
7. When, and from which IP address, the message was opened (and that the address is live). Analyse suspect mail offline with a parser, never in a mail client that loads remote content.
8. In the `__substg1.0_007D001F` stream (`PR_TRANSPORT_MESSAGE_HEADERS`). Drafts and most sent items never went through transport on the way in, and some exports or conversions drop the property.

</details>

---

## 📚 Further reading

- Microsoft, *[MS-PST]: Outlook Personal Folders (.pst) File Format* and *[MS-OXMSG]: Outlook Item (.msg) File Format*
- Joachim Metz, *PFF forensics: analyzing the horrible reference file format* and *PFF forensics: e-mail and appointment falsification analysis* (https://github.com/libyal/documentation)
- RFC 5322 (Internet Message Format), RFC 2045–2049 (MIME), RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC), RFC 8601 (Authentication-Results)
- libpst (https://www.five-ten-sg.com/libpst/) and libpff (https://github.com/libyal/libpff)
- EDRM, *Enron Data Set*: the source of the PST in Lab 2

---

## ⏭️ Tomorrow: Day 20

**Volume Shadow Copies & BitLocker volumes.** Tools: **libvshadow**, **dislocker**, **ShadowExplorer**.
Today a PST could hide deleted items until compaction; tomorrow Windows itself keeps older copies of whole volumes. How to find shadow copies in an image, mount them read-only, and open BitLocker-encrypted volumes when you have the key.

---

<sub>Part of the <a href="../README.md">DFIR Daily</a> series · <a href="../CURRICULUM.md">Full 60-day curriculum</a> · For educational and authorised use only.</sub>
