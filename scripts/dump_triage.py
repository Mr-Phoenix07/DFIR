#!/usr/bin/env python3
"""dump_triage.py - identify and read the header of on-disk memory artifacts.

Usage: dump_triage.py FILE [FILE ...]

Before you reach for Hibernation Recon, WinDbg or Volatility, say what each file is and read what
its header already tells you:

  * Windows kernel crash dump (_DUMP_HEADER64 / _DUMP_HEADER): signature PAGE + DU64/DUMP, NT
    version, machine type, processor count, and the bug-check code + first parameter (the stop code);
  * Windows minidump (MDMP) - a user-mode dump WinDbg opens directly;
  * Windows hibernation file (HIBR/hibr/WAKE/RSTR, or zeroed when clean) - the compressed RAM
    snapshot that Hibernation Recon / Volatility decompress;
  * anything else - a raw/padded physical image (Day 23) or a pagefile/swap slice (unstructured
    paged-out memory, best triaged with strings/bstrings).

It reads only the header; it does not decompress or parse physical-memory runs. Standard library only.
"""
import struct
import sys

BUGCHECKS = {0x7E: "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", 0x50: "PAGE_FAULT_IN_NONPAGED_AREA",
             0xD1: "DRIVER_IRQL_NOT_LESS_OR_EQUAL", 0x1E: "KMODE_EXCEPTION_NOT_HANDLED",
             0x3B: "SYSTEM_SERVICE_EXCEPTION", 0x139: "KERNEL_SECURITY_CHECK_FAILURE",
             0xEF: "CRITICAL_PROCESS_DIED"}
MACHINES = {0x8664: "x64 (AMD64)", 0x14C: "x86 (i386)", 0xAA64: "ARM64"}


def crashdump(data):
    valid = data[4:8]
    bits = "x64" if valid == b"DU64" else "x86" if valid == b"DUMP" else "?"
    major, minor = struct.unpack_from("<II", data, 0x08)
    machine, nproc = struct.unpack_from("<II", data, 0x30), None
    machine = struct.unpack_from("<I", data, 0x30)[0]
    nproc = struct.unpack_from("<I", data, 0x34)[0]
    bug = struct.unpack_from("<I", data, 0x38)[0]
    param1 = struct.unpack_from("<Q", data, 0x40)[0]
    print(f"  type:    Windows kernel crash dump ({bits})  -> WinDbg, or Volatility crash layer")
    print(f"  version: NT {major}.{minor}   machine: {MACHINES.get(machine, hex(machine))}   processors: {nproc}")
    print(f"  bugcheck: {bug:#x} {BUGCHECKS.get(bug, '(see MS stop-code list)')}   param1: {param1:#018x}")


def main(paths):
    for i, path in enumerate(paths):
        if i:
            print()
        print(path)
        try:
            with open(path, "rb") as f:
                data = f.read(0x2000)
        except OSError as e:
            print(f"  cannot read: {e}")
            continue
        sig4 = data[:4]
        if sig4 == b"PAGE":
            crashdump(data)
        elif sig4 == b"MDMP":
            ver = struct.unpack_from("<I", data, 6)[0] if len(data) >= 8 else 0
            print(f"  type:    Windows user-mode minidump (MDMP)  -> WinDbg (.dmp), streams v{ver:#x}")
        elif sig4 in (b"HIBR", b"hibr", b"WAKE", b"RSTR"):
            print(f"  type:    Windows hibernation file (signature {sig4.decode('latin-1')!r})"
                  f"  -> Hibernation Recon / Volatility (decompress Xpress-Huffman)")
            print("  state:   contains a hibernated RAM image (compressed); decompress before analysis")
        elif sig4 == b"EMiL":
            print("  type:    LiME-format memory image (Day 26)  -> Volatility lime layer")
        elif set(data[:16]) == {0}:
            print("  type:    starts with zeroes - a clean/reset hiberfil, or a sparse/padded image")
        else:
            print("  type:    no known header -> raw/padded physical image, or a pagefile/swap slice")
            print("           (unstructured paged-out memory; carve with strings / bstrings)")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(sys.argv[1:])
