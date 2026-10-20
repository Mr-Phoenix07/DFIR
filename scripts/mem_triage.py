#!/usr/bin/env python3
"""mem_triage.py - first-pass triage of a raw memory image, before a framework like Volatility.

Usage: mem_triage.py IMAGE [--min N] [--entropy T]

Works on any flat/raw physical-memory dump - what WinPmem, Magnet RAM Capture and Belkasoft Live
RAM Capturer all write - and does the quick questions you ask before loading a profile into
Volatility (Day 24):

  * how big is it, and does its hash match what the acquisition tool reported (integrity);
  * what readable text is in it, in BOTH ASCII and UTF-16LE (Windows keeps most strings wide, so an
    ASCII-only `strings` misses half the evidence);
  * indicators worth grepping for straight away: URLs, IPv4 addresses, UNC paths, a leaked
    credential, and a `powershell -enc` blob (which it base64-decodes to show the real command);
  * high-entropy pages, which stand out as encrypted or packed payloads staged in memory.

It reads the file in a single pass and reports byte offsets so you can seek back to anything. It does
NOT parse OS structures (process list, DLLs, handles, network table) - that needs a memory framework
with the right symbols, which is tomorrow. Standard library only.
"""
import argparse
import base64
import hashlib
import math
import re
import sys

PAGE = 4096
PRINTABLE = set(range(0x20, 0x7F)) | {0x09}

IOC = [
    ("URL", re.compile(rb"https?://[^\s\"'<>\\]{4,120}")),
    ("IPv4", re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("UNC", re.compile(rb"\\\\[A-Za-z0-9._-]+\\[^\s\"'<>]{1,80}")),
    ("cred", re.compile(rb"(?i)(?:password|passwd|pwd)\s*[:=]\s*\S{1,40}")),
    ("enc", re.compile(rb"(?i)-e(?:nc|ncodedcommand)?\s+([A-Za-z0-9+/]{20,}={0,2})")),
]


def ascii_runs(data, minlen):
    """Yield (offset, text) for printable ASCII runs of at least minlen bytes."""
    start, run = None, bytearray()
    for i, b in enumerate(data):
        if b in PRINTABLE:
            if start is None:
                start = i
            run.append(b)
        else:
            if start is not None and len(run) >= minlen:
                yield start, run.decode("latin-1")
            start, run = None, bytearray()
    if start is not None and len(run) >= minlen:
        yield start, run.decode("latin-1")


def utf16_runs(data, minlen):
    """Yield (offset, text) for printable UTF-16LE runs (char, 0x00) of at least minlen chars."""
    start, run = None, bytearray()
    i, n = 0, len(data) - 1
    while i < n:
        lo, hi = data[i], data[i + 1]
        if hi == 0 and lo in PRINTABLE:
            if start is None:
                start = i
            run.append(lo)
            i += 2
            continue
        if start is not None and len(run) >= minlen:
            yield start, run.decode("latin-1")
        start, run = None, bytearray()
        i += 1
    if start is not None and len(run) >= minlen:
        yield start, run.decode("latin-1")


def entropy(block):
    counts = [0] * 256
    for b in block:
        counts[b] += 1
    h, length = 0.0, len(block)
    for c in counts:
        if c:
            p = c / length
            h -= p * math.log2(p)
    return h


def main(path, minlen, thresh):
    data = open(path, "rb").read()
    print("== image ==")
    print(f"file: {path}   size: {len(data)} bytes   pages: {len(data)//PAGE} x {PAGE}")
    print(f"sha256: {hashlib.sha256(data).hexdigest()}")

    strings = [(off, t, "A") for off, t in ascii_runs(data, minlen)]
    strings += [(off, t, "W") for off, t in utf16_runs(data, minlen)]
    na = sum(1 for s in strings if s[2] == "A")
    nw = sum(1 for s in strings if s[2] == "W")
    print("\n== strings ==")
    print(f"ASCII (>={minlen}):    {na}")
    print(f"UTF-16LE (>={minlen}): {nw}")

    print("\n== indicators ==")
    hits = []
    for off, text, _ in strings:
        raw = text.encode("latin-1")
        for label, rx in IOC:
            for m in rx.finditer(raw):
                value = m.group(0).decode("latin-1")
                hits.append((off + m.start(), label, value))
    for off, label, value in sorted(set(hits)):
        line = f"[{label:4}] 0x{off:08x}  {value}"
        if label == "enc":
            b64 = re.search(r"[A-Za-z0-9+/]{20,}={0,2}", value).group(0)
            try:
                decoded = base64.b64decode(b64).decode("utf-16-le", "replace")
                line += f"\n             decodes to: {decoded}"
            except Exception:
                pass
        print(line)

    print("\n== high-entropy pages (> {:.1f} bits/byte) ==".format(thresh))
    flagged = 0
    for off in range(0, len(data) - PAGE + 1, PAGE):
        h = entropy(data[off:off + PAGE])
        if h > thresh:
            print(f"0x{off:08x}  entropy {h:.2f}")
            flagged += 1
    if not flagged:
        print("(none)")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("image")
    ap.add_argument("--min", type=int, default=6, dest="minlen")
    ap.add_argument("--entropy", type=float, default=7.5)
    a = ap.parse_args()
    try:
        main(a.image, a.minlen, a.entropy)
    except BrokenPipeError:
        sys.exit(0)
