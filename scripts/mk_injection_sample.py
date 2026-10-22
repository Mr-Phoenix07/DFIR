#!/usr/bin/env python3
"""mk_injection_sample.py - a raw memory slice with in-memory malcode artifacts, for the Day 25 labs.

Usage: python3 mk_injection_sample.py OUT [--size-mib N]

Day 23 built a flat triage sample; this one carries the kinds of artifact you hunt when looking for
*malicious code hidden inside a process* - injection, hollowing and loose shellcode - so YARA rules
have something real to match. Like the others it is byte-identical on every run, laid out in 4 KiB
pages, and tied to the WS-ALICE intrusion (the stage-2 payload from Day 23, now resident in a
victim process). Planted, each at a known page:

  * a classic x86 shellcode prologue (the Metasploit "block API" stub: cld; call; pushad; ...);
  * an injected PE: an `MZ`/`PE` header and the "This program cannot be run in DOS mode" stub, sitting
    in memory with no file on disk behind it (process hollowing / reflective injection);
  * the export name `ReflectiveLoader` (reflective DLL injection);
  * the injection API set (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread,
    NtUnmapViewOfSection, LoadLibraryA, GetProcAddress);
  * the WS-ALICE C2 (203.0.113.50) in UTF-16LE;
  * one high-entropy page (the still-encrypted part of the payload).

It is NOT a real process image - there are no VADs or page permissions, so a real PE-sieve/Moneta run
(which reason about private vs mapped, +x regions) needs a live Windows host. Here the point is the
signature hunting YARA does on any buffer. Standard library only.
"""
import argparse
import hashlib
import struct
import sys

PAGE = 4096

# Metasploit "block API" shellcode prologue (the real, widely-signatured opening bytes):
#   fc            cld
#   e8 82 00 00 00  call +0x82
#   60            pushad
#   89 e5         mov ebp, esp
#   31 c0         xor eax, eax
#   64 8b 50 30   mov edx, fs:[eax+0x30]
#   8b 52 0c      mov edx, [edx+0x0c]
#   8b 52 14      mov edx, [edx+0x14]
SHELLCODE = bytes.fromhex("fce882000000608 9e531c0648b50308b520c8b5214".replace(" ", ""))

DOS_STUB = b"This program cannot be run in DOS mode.\r\r\n$"


def injected_pe():
    """A minimal in-memory PE header image: MZ, e_lfanew -> 'PE\\0\\0', and the DOS-mode stub."""
    buf = bytearray(256)
    buf[0:2] = b"MZ"
    buf[0x3C:0x40] = struct.pack("<I", 0x80)   # e_lfanew -> PE header at 0x80
    buf[0x4E:0x4E + len(DOS_STUB)] = DOS_STUB
    buf[0x80:0x86] = b"PE\x00\x00\x4c\x01"     # PE signature + IMAGE_FILE_MACHINE_I386
    return bytes(buf)


def entropy_page(tag):
    out = bytearray()
    i = 0
    while len(out) < PAGE:
        out += hashlib.sha256(tag + struct.pack("<I", i)).digest()
        i += 1
    return bytes(out[:PAGE])


APIS = b"\x00".join([b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread",
                     b"NtUnmapViewOfSection", b"LoadLibraryA", b"GetProcAddress"]) + b"\x00"

ARTIFACTS = [
    (50, SHELLCODE + b"\x90" * 16),                                   # shellcode stub + NOP sled
    (120, injected_pe()),                                            # injected/hollowed PE header
    (200, b"ReflectiveLoader\x00" + APIS),                           # reflective loader + injection APIs
    (240, "http://203.0.113.50/gate.php".encode("utf-16-le") + b"\x00\x00"),  # C2 config (wide)
    (777, entropy_page(b"ws-alice-stage2")),                         # encrypted remainder of payload
]


def main(out, size_mib):
    size = size_mib * 1024 * 1024
    buf = bytearray(size)
    for page, data in ARTIFACTS:
        off = page * PAGE
        if off + len(data) > size:
            sys.exit(f"artifact at page {page} does not fit in {size_mib} MiB")
        buf[off:off + len(data)] = data
    with open(out, "wb") as f:
        f.write(buf)
    print(f"wrote {out}: {size} bytes ({size // PAGE} pages of {PAGE}), {len(ARTIFACTS)} artifact pages")
    print(f"sha256: {hashlib.sha256(buf).hexdigest()}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("out")
    ap.add_argument("--size-mib", type=int, default=8)
    a = ap.parse_args()
    main(a.out, a.size_mib)
